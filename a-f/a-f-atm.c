

#include "header.h"


/*
 * This is the top level routine of the printer.  'p' points
 * to the LLC/SNAP header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
void atm_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}