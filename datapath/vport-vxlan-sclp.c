/*
 * Copyright (c) 2015 Ryota Kawashima <kawa1983@ieee.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/rculist.h>
#include <linux/sclp.h>
#include <net/vxlan.h>
#include <net/sclp_tunnel.h>
#include "datapath.h"
#include "vport.h"


#define VXLAN_FLAGS 0x08000000

/* VXLAN protocol header */
struct vxlanhdr {
    __be32 vx_flags;
    __be32 vx_vni;
};


/**
 * struct vxlsclp_port - Keeps track of open SCLP ports
 * @sock: socket created for the port.
 * @name: vport name.
 */
struct vxlsclp_port {
    struct list_head list;
    struct vport *vport;
    struct socket *sock;
    struct rcu_head rcu;
    char name[IFNAMSIZ];
};

static LIST_HEAD(vxlan_sclp_ports);


static inline struct vxlsclp_port *vxlan_sclp_vport(const struct vport *vport)
{
    return vport_priv(vport);
}


static inline struct vxlanhdr *vxlan_sclp_hdr(const struct sk_buff *skb)
{
    return (struct vxlanhdr*)skb->data;
}


static struct vxlsclp_port *vxlan_sclp_find_port(struct net *net, __be16 port)
{
    struct vxlsclp_port *vxlsclp_port;

    list_for_each_entry_rcu(vxlsclp_port, &vxlan_sclp_ports, list) {
	__be16 dst_port = inet_sport(vxlsclp_port->sock->sk);

	if ((dst_port == port) &&
	    net_eq(sock_net(vxlsclp_port->sock->sk), net)) {
	    return vxlsclp_port;
	}
    }

    return NULL;
}


static int vxlan_sclp_set_inner(struct sk_buff *skb)
{
    struct ethhdr *ether;

    skb_reset_mac_header(skb);
    ether = (struct ethhdr*)skb_mac_header(skb);

    if (ether->h_proto == htons(ETH_P_8021Q)) {
	struct vlan_ethhdr *vlan;
	if (unlikely(!pskb_may_pull(skb, sizeof(struct vlan_ethhdr))))
	    return -EPROTO;
	vlan = (struct vlan_ethhdr*)ether;
	skb_set_network_header(skb, sizeof(*vlan));
	skb->protocol = vlan->h_vlan_encapsulated_proto;
    } else {
	skb_set_network_header(skb, sizeof(*ether));
	skb->protocol = ether->h_proto;
    }

    skb_reset_transport_header(skb);

    return 0;
}


static int vxlan_sclp_handle_gso_tp(struct sk_buff *skb, int protocol, size_t iph_len, int ipv6)
{
    skb_set_transport_header(skb, skb_network_offset(skb) + iph_len);
    skb->csum_start = skb_headroom(skb) + skb_transport_offset(skb);

    if (protocol == IPPROTO_TCP) {
	skb_shinfo(skb)->gso_size = 1500 - sizeof(iph_len) - sizeof(struct tcphdr);
	skb_shinfo(skb)->gso_type |= (ipv6) ? SKB_GSO_TCPV6 : SKB_GSO_TCPV4;
	skb->csum_offset = offsetof(struct tcphdr, check);
    } else if (protocol == IPPROTO_UDP) {
	skb_shinfo(skb)->gso_size = 1500 - sizeof(iph_len) - sizeof(struct udphdr);
	skb_shinfo(skb)->gso_type |= SKB_GSO_UDP;
	skb->csum_offset = offsetof(struct udphdr, check);
    } else {
	pr_warn("Unsupported L4 protocol: %d\n", protocol);
	return -EPROTO;
    }

    return 0;
}


static int vxlan_sclp_handle_gso_4(struct sk_buff *skb)
{
    struct iphdr *iph;
    size_t iph_len;

    if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
	return -EPROTO;

    iph = (struct iphdr*)skb_network_header(skb);
    iph_len = iph->ihl << 2;

    return vxlan_sclp_handle_gso_tp(skb, iph->protocol, iph_len, 0);
}


static int vxlan_sclp_handle_gso_6(struct sk_buff *skb)
{
    struct ipv6hdr *iph;
    size_t iph_len;

    if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
	return -EPROTO;

    iph = (struct ipv6hdr*)skb_network_header(skb);
    iph_len = skb->len - skb_network_offset(skb) - ntohs(iph->payload_len);

    return vxlan_sclp_handle_gso_tp(skb, iph->nexthdr, iph_len, 1);
}


static int vxlan_sclp_handle_gso(struct sk_buff *skb)
{
    skb_shinfo(skb)->gso_segs = 0;

    if (skb->len - ETH_HLEN <= 1500) {
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return 0;
    }

    skb_shinfo(skb)->gso_type = SKB_GSO_DODGY;
    skb->ip_summed = CHECKSUM_PARTIAL;

    if (skb->protocol == htons(ETH_P_IP)) {
	return vxlan_sclp_handle_gso_4(skb);
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
	return vxlan_sclp_handle_gso_6(skb);
    }

    pr_warn("Unsupported L3 protocol: 0x%X\n", ntohs(skb->protocol));
    return -EPROTO;
}


/* Called with rcu_read_lock and BH disabled. */
static int vxlan_sclp_rcv(struct sock *sock, struct sk_buff *skb)
{
    struct ovs_key_ipv4_tunnel tun_key;
    struct vxlsclp_port *vxlsclp_port;
    struct vxlanhdr *vxlh;
    struct iphdr *iph;
    __be64 key;
    __be32 vni;

    if (unlikely(!pskb_may_pull(skb, sizeof(struct vxlanhdr) + ETH_HLEN)))
	goto error;

    vxlsclp_port = vxlan_sclp_find_port(dev_net(skb->dev), sclp_hdr(skb)->dest);
    if (unlikely(!vxlsclp_port))
	goto error;

    vxlh = vxlan_sclp_hdr(skb);
    if (unlikely(vxlh->vx_flags != htonl(VXLAN_FLAGS) ||
		 vxlh->vx_vni & htonl(0xFF)))
	goto error;

    vni = ntohl(vxlh->vx_vni) >> 8;

    /* Save outer tunnel values */
    iph = ip_hdr(skb);
    key = cpu_to_be64(vni);
    ovs_flow_tun_key_init(&tun_key, iph, key, TUNNEL_KEY);

    if (iptunnel_pull_header(skb, sizeof(struct vxlanhdr), htons(ETH_P_TEB)))
	goto drop;

    if (unlikely(vxlan_sclp_set_inner(skb)))
	goto drop;

    if (unlikely(vxlan_sclp_handle_gso(skb)))
	goto drop;

    rcu_read_lock();
    ovs_vport_receive(vxlsclp_port->vport, skb, &tun_key);
    rcu_read_unlock();

    return PACKET_RCVD;

drop:
    kfree_skb(skb);
    return NET_RX_DROP;

error:
    return PACKET_REJECT;
}


static int vxlan_sclp_socket_init(struct vxlsclp_port *vxlsclp_port, struct net *net, __be16 dst_port)
{
    struct sclp_port_cfg port_cfg;
    struct sclp_tunnel_sock_cfg tnl_cfg;
    struct in_addr addr;
    int err;

    addr.s_addr = htonl(INADDR_ANY);

    port_cfg.family = AF_INET;
    port_cfg.local_ip = addr;
    port_cfg.local_sclp_port = dst_port;
    port_cfg.peer_sclp_port = 0;

    err = sclp_sock_create(net, &port_cfg, &vxlsclp_port->sock);
    if (err)
	goto out;

    tnl_cfg.encap_rcv = vxlan_sclp_rcv;

    setup_sclp_tunnel_sock(net, vxlsclp_port->sock, &tnl_cfg);

out:
    return err;
}


static int vxlan_sclp_tnl_setup(struct net *net, struct vxlsclp_port *vxlsclp_port, __be16 dst_port)
{
    int err;

    /* Verify if we already have a socket created for this port */
    if (vxlan_sclp_find_port(net, dst_port)) {
	err = -EEXIST;
	goto out;
    }

    list_add_tail_rcu(&vxlsclp_port->list, &vxlan_sclp_ports);

    err = vxlan_sclp_socket_init(vxlsclp_port, net, dst_port);
    if (err)
	goto error;

    return 0;

error:
    list_del_rcu(&vxlsclp_port->list);
out:
    return err;
}


static struct vport *vxlan_sclp_tnl_create(const struct vport_parms *parms)
{
    struct nlattr *options = parms->options;
    struct vxlsclp_port *vxlsclp_port;
    struct vport *vport;
    struct nlattr *a;
    u16 dst_port;
    int err;

    if (!options) {
	err = -EINVAL;
	goto error;
    }

    a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
    if (a && nla_len(a) == sizeof(u16)) {
	dst_port = nla_get_u16(a);
    } else {
	/* Require destination port from userspace. */
	err = -EINVAL;
	goto error;
    }

    vport = ovs_vport_alloc(sizeof(struct vxlsclp_port),
			    &ovs_vxlan_sclp_vport_ops, parms);
    if (IS_ERR(vport))
	return vport;

    vxlsclp_port = vxlan_sclp_vport(vport);
    strncpy(vxlsclp_port->name, parms->name, IFNAMSIZ);

    err = vxlan_sclp_tnl_setup(ovs_dp_get_net(parms->dp), vxlsclp_port, htons(dst_port));
    if (unlikely(err)) {
	ovs_vport_free(vport);
	goto error;
    }

    vxlsclp_port->vport = vport;

    return vport;

error:
    return ERR_PTR(err);
}


static void vxlan_sclp_tnl_destroy(struct vport *vport)
{
    struct vxlsclp_port *vxlsclp_port = vxlan_sclp_vport(vport);

    if (vxlsclp_port) {
	list_del_rcu(&vxlsclp_port->list);

	sclp_tunnel_sock_release(vxlsclp_port->sock);
    }

    ovs_vport_deferred_free(vport);
}


static int vxlan_sclp_init_output_skb(struct sk_buff *skb, const struct rtable *rt)
{
    size_t min_headroom;
    int err;

    skb->tstamp.tv64 = 0;
    skb->pkt_type = PACKET_HOST;
    skb->local_df = 0;
    skb_dst_drop(skb);
    skb->mark = 0;
    secpath_reset(skb);
    nf_reset(skb);

    min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) 
	+ rt_dst(rt).header_len
	+ sizeof(struct vxlanhdr)
	+ sizeof(struct sclphdr)
	+ sizeof(struct iphdr)
	+ (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);

    err = skb_cow_head(skb, min_headroom);
    if (unlikely(err))
	return err;

    if (vlan_tx_tag_present(skb)) {
	if (! __vlan_put_tag(skb, skb->vlan_proto, vlan_tx_tag_get(skb)))
	    return -ENOMEM;
	skb->vlan_tci = 0;
    }

    return err;
}


static int vxlan_sclp_set_vxlan(struct vxlsclp_port *vxlsclp_port, struct sk_buff *skb)
{
    struct vxlanhdr *vxlh;

    skb_push(skb, sizeof(struct vxlanhdr));

    vxlh = (struct vxlanhdr*)vxlan_sclp_hdr(skb);
    vxlh->vx_flags = htonl(VXLAN_FLAGS);
    vxlh->vx_vni = htonl(be64_to_cpu(OVS_CB(skb)->tun_key->tun_id) << 8);

    return 0;
}


static void vxlan_sclp_sock_put(struct sk_buff *skb)
{
    sock_put(skb->sk);
}


static void vxlan_sclp_set_owner(struct sock* sk, struct sk_buff *skb)
{
    skb_orphan(skb);
    sock_hold(sk);
    skb->sk = sk;
    skb->destructor = vxlan_sclp_sock_put;
}


static int vxlan_sclp_tnl_send(struct vport *vport, struct sk_buff *skb)
{
    struct vxlsclp_port *vxlsclp_port = vxlan_sclp_vport(vport);
    struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;
    struct rtable *rt;
    __be16 src_port;
    __be16 dst_port;
    __be32 saddr;
    __be32 daddr;
    __be16 df;
    int port_min;
    int port_max;
    int err;

    if (unlikely(!tun_key)) {
	err = -EINVAL;
	goto error;
    }

    daddr = tun_key->ipv4_dst;
    saddr = tun_key->ipv4_src;

    /* Route lookup */
    rt = find_route(ovs_dp_get_net(vport->dp),
		    &saddr,
		    tun_key->ipv4_dst,
		    IPPROTO_SCLP,
		    tun_key->ipv4_tos,
		    skb->mark);
    if (IS_ERR(rt)) {
	err = PTR_ERR(rt);
	goto error;
    }

    df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;

    skb->local_df = 1;

    inet_get_local_port_range(ovs_dp_get_net(vport->dp), &port_min, &port_max);
    src_port = vxlan_src_port(port_min, port_max, skb);
    dst_port = inet_sport(vxlsclp_port->sock->sk);

    err = vxlan_sclp_init_output_skb(skb, rt);
    if (err)
	goto error;

    vxlan_sclp_set_vxlan(vxlsclp_port, skb);

    vxlan_sclp_set_owner(vxlsclp_port->sock->sk, skb);

    err = sclp_tunnel_xmit_skb(skb, rt, daddr, saddr, 
			       tun_key->ipv4_tos, 
			       tun_key->ipv4_ttl, 
			       df, dst_port, src_port);
    if (err < 0)
	ip_rt_put(rt);

error:
    return err;
}


static const char *vxlan_sclp_get_name(const struct vport *vport)
{
    struct vxlsclp_port *vxlsclp_port = vxlan_sclp_vport(vport);

    return vxlsclp_port->name;
}


static int vxlan_sclp_get_options(const struct vport *vport, struct sk_buff *skb)
{
    struct vxlsclp_port *vxlsclp_port = vxlan_sclp_vport(vport);
    __be16 dst_port = inet_sport(vxlsclp_port->sock->sk);

    if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(dst_port))) {
	return -EMSGSIZE;
    }

    return 0;
}


const struct vport_ops ovs_vxlan_sclp_vport_ops = {
    .type        = OVS_VPORT_TYPE_VXLAN_SCLP,
    .create      = vxlan_sclp_tnl_create,
    .destroy     = vxlan_sclp_tnl_destroy,
    .get_name    = vxlan_sclp_get_name,
    .get_options = vxlan_sclp_get_options,
    .send        = vxlan_sclp_tnl_send,
};
