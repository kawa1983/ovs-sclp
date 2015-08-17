#ifndef _LINUX_SCLP_H
#define _LINUX_SCLP_H

#include <linux/skbuff.h>
#include <net/inet_sock.h>
#include <uapi/linux/sclp.h>


static inline struct sclphdr *sclp_hdr(const struct sk_buff *skb)
{
    return (struct sclphdr*)skb_transport_header(skb);
}


struct sclp_sock
{
    struct inet_sock inet;
    int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
};


static inline struct sclp_sock *sclp_sk(const struct sock *sk)
{
    return (struct sclp_sock*)sk;
}

#endif /* _LINUX_SCLP_H */
