

#include "header.h"

static inline const char *
get_etheraddr_string(ndo_t *ndo, const uint8_t *p)
{
    if (!ND_TTEST_LEN(p, MAC_ADDR_LEN))
        nd_trunc_longjmp(ndo);
    return etheraddr_string(ndo, p);
}