
#ifndef __ADDRTONAME_H__
#define __ADDRTONAME_H__

#include "ndo.h"
#include "a-f-extract.h"

/* Name to address translation routines. */

enum
{
    LINKADDR_ETHER,
    LINKADDR_FRELAY,
    LINKADDR_IEEE1394,
    LINKADDR_ATM,
    LINKADDR_OTHER
};

#define BUFSIZE 128

extern const char *etheraddr_string(ndo_t *, const uint8_t *);
extern const char *ipaddr_string(ndo_t*, const u_char *);
extern const char *ip6addr_string(ndo_t *, const u_char *);

static inline const char *
get_etheraddr_string(ndo_t *ndo, const uint8_t *p)
{
    if (!ND_TTEST_LEN(p, MAC_ADDR_LEN))
        nd_trunc_longjmp(ndo);
    return etheraddr_string(ndo, p);
}

static inline const char *
get_ipaddr_string(ndo_t *ndo, const u_char *p)
{
    if (!ND_TTEST_4(p))
        nd_trunc_longjmp(ndo);
    return ipaddr_string(ndo, p);
}

static inline const char *
get_ip6addr_string(ndo_t *ndo, const u_char *p)
{
    if (!ND_TTEST_16(p))
        nd_trunc_longjmp(ndo);
    return ip6addr_string(ndo, p);
}

#define GET_IPADDR_STRING(p) get_ipaddr_string(ndo, (const u_char *)(p))
#define GET_IP6ADDR_STRING(p) get_ip6addr_string(ndo, (const u_char *)(p))

#endif