
#include "header.h"

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->len' is the length
 * of the packet off the wire, and 'h->caplen' is the number
 * of bytes actually captured.
 */
void ether_if_print(void * infonode, const struct pcap_pkthdr *h, const u_char *p)
{
    TI("Called { %s (%p, %p, %p)", __func__, infonode, h, p);

    TI("Enter");

    RVoid();
}


/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->len' is the length
 * of the packet off the wire, and 'h->caplen' is the number
 * of bytes actually captured.
 *
 * This is for DLT_NETANALYZER, which has a 4-byte pseudo-header
 * before the Ethernet header.
 */
void netanalyzer_if_print(void * infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->len' is the length
 * of the packet off the wire, and 'h->caplen' is the number
 * of bytes actually captured.
 *
 * This is for DLT_NETANALYZER_TRANSPARENT, which has a 4-byte
 * pseudo-header, a 7-byte Ethernet preamble, and a 1-byte Ethernet SOF
 * before the Ethernet header.
 */
void netanalyzer_transparent_if_print(void * infonode,
                                      const struct pcap_pkthdr *h,
                                      const u_char *p)
{

    return ;
}