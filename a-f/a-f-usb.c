
#include "header.h"

/*
 * This is the top level routine of the printer for captures with a
 * 48-byte header.
 *
 * 'p' points to the header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
void usb_linux_48_byte_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h _U_, const u_char *p)
{

    return ;
}


#ifdef DLT_USB_LINUX_MMAPPED
/*
 * This is the top level routine of the printer for captures with a
 * 64-byte header.
 *
 * 'p' points to the header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
void usb_linux_64_byte_if_print(void *ndo, void *infonode, const struct pcap_pkthdr *h _U_, const u_char *p)
{

    return ;
}
#endif /* DLT_USB_LINUX_MMAPPED */