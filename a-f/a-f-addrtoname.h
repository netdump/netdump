
#ifndef __ADDRTONAME_H__
#define __ADDRTONAME_H__

#include "ndo.h"

#define BUFSIZE 128

extern void etheraddr_string(ndo_t *, const uint8_t *, char *roomage);

static inline void
fill_etheraddr_string(ndo_t *ndo, const uint8_t *p, char * roomage)
{
    if (!ND_TTEST_LEN(ndo, p, MAC_ADDR_LEN))
        nd_trunc_longjmp(ndo);
    return etheraddr_string(ndo, p, roomage);
}


#endif