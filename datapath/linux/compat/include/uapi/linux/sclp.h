#ifndef _UAPI_LINUX_SCLP_H
#define _UAPI_LINUX_SCLP_H
 
#include <linux/types.h>
#include <asm/byteorder.h>

#ifndef IPPROTO_SCLP
#define IPPROTO_SCLP        234
#endif

#ifndef NEXTHDR_SCLP
#define NEXTHDR_SCLP        234
#endif

#ifndef SOL_SCLP
#define SOL_SCLP            234
#endif

#ifndef SOCK_SCLP
#define SOCK_SCLP           7
#endif

#define SCLP_ID_MASK        0xFFFFFFFE


struct sclphdr
{
    __be16 source;          /* Source port */
    __be16 dest;            /* Destination port */
    __be32 id;
    __be16 rem;             /* Remaining length */
    __be16 check;           /* Checksum */
} __attribute__ ((packed));


static inline void sclp_set_first_segment(struct sclphdr *sclp)
{
    sclp->id |= htonl(~SCLP_ID_MASK);
}

static inline bool sclp_is_first_segment(const struct sclphdr *sclp)
{
    return (sclp->id & htonl(~SCLP_ID_MASK));
}

#endif /* _UAPI_LINUX_SCLP_H */

