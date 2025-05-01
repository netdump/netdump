

#include "header.h"


#define INVALIDTIMESTAMP        "00:00:00.000000"


/*
 * Print the timestamp as HH:MM:SS.FRAC.
 */
static void ts_hmsfrac_print(ndo_t *ndo, const struct timeval *tv, char * timestamp)
{

    TI("Called { %s(%p, %p, %p)}", __func__, ndo, tv, timestamp);

    struct tm *tm = tm = localtime(&tv->tv_sec);

    if (!tm) 
    {
        memcpy(timestamp, INVALIDTIMESTAMP, strlen(INVALIDTIMESTAMP));
        RVoid();
    }

    if (strftime(timestamp, strlen(INVALIDTIMESTAMP), "%H:%M:%S", tm) == 0)
    {
        memcpy(timestamp, INVALIDTIMESTAMP, strlen(INVALIDTIMESTAMP));
        RVoid();
    }

    sprintf((timestamp + strlen(timestamp)), ".%06u", (unsigned)tv->tv_usec);

    RVoid();
}


/**
 * @brief
 *  
 */
void analysis_ts_print(ndo_t * ndo, const struct timeval *tv, char *timestamp)
{
    TC("Called { %s (%p, %p, %p)", __func__, ndo, tv, timestamp);

    if (!ndo || !tv || !timestamp)
    {
        memcpy(timestamp, INVALIDTIMESTAMP, strlen(INVALIDTIMESTAMP));
        RVoid();
    }

    if (tv->tv_sec < 0)
    {
        memcpy(timestamp, INVALIDTIMESTAMP, strlen(INVALIDTIMESTAMP));
        RVoid();
    }

    ts_hmsfrac_print(ndo, tv, timestamp);

    RVoid();
}