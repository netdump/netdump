
#include "header.h"

/*
 * This is the top level routine of the printer.  'p' points
 * to the 802.11 header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
void ieee802_11_if_print(ndo_t * ndo, void * infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}


/*
 * For DLT_IEEE802_11_RADIO; like DLT_IEEE802_11, but with an extra
 * header, containing information such as radio information.
 */
void ieee802_11_radio_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}


/*
    * For DLT_IEEE802_11_RADIO_AVS; like DLT_IEEE802_11, but with an
    * extra header, containing information such as radio information,
    * which we currently ignore.
    */
void ieee802_11_radio_avs_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return;
}


/*
 * For DLT_PRISM_HEADER; like DLT_IEEE802_11, but with an extra header,
 * containing information such as radio information, which we
 * currently ignore.
 *
 * If, however, the packet begins with WLANCAP_MAGIC_COOKIE_V1 or
 * WLANCAP_MAGIC_COOKIE_V2, it's really DLT_IEEE802_11_RADIO_AVS
 * (currently, on Linux, there's no ARPHRD_ type for
 * DLT_IEEE802_11_RADIO_AVS, as there is a ARPHRD_IEEE80211_PRISM
 * for DLT_PRISM_HEADER, so ARPHRD_IEEE80211_PRISM is used for
 * the AVS header, and the first 4 bytes of the header are used to
 * indicate whether it's a Prism header or an AVS header).
 */
void prism_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{


    return ;
}