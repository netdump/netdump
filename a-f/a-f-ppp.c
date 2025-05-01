
#include "header.h"

/* BSD/OS specific PPP printer */
void ppp_bsdos_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h _U_, const u_char *p _U_)
{


    return ;
}


/*
 * PPP I/F printer to use if we know that RFC 1662-style PPP in HDLC-like
 * framing, or Cisco PPP with HDLC framing as per section 4.3.1 of RFC 1547,
 * is being used (i.e., we don't check for PPP_ADDRESS and PPP_CONTROL,
 * discard them *if* those are the first two octets, and parse the remaining
 * packet as a PPP packet, as "ppp_print()" does).
 *
 * This handles, for example, DLT_PPP_SERIAL in NetBSD.
 */
void ppp_hdlc_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{


    return ;
}


/* PPP I/F printer */
void ppp_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{


    return ;
}