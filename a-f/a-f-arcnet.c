
#include "header.h"

/*
 * This is the top level routine of the printer.  'p' points
 * to the ARCNET header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
void arcnet_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}


/*
 * This is the top level routine of the printer.  'p' points
 * to the ARCNET header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.  It is quite similar
 * to the non-Linux style printer except that Linux doesn't ever
 * supply packets that look like exception frames, it always supplies
 * reassembled packets rather than raw frames, and headers have an
 * extra "offset" field between the src/dest and packet type.
 */
void arcnet_linux_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}