
#include "header.h"

/*
 * Length of an Ethernet header; note that some compilers may pad
 * "struct ether_header" to a multiple of 4 bytes, for example, so
 * "sizeof (struct ether_header)" may not give the right answer.
 */
#define ETHER_HDRLEN                            (14U)


/*
 * Structure of an Ethernet header.
 */
struct ether_header
{
    nd_mac_addr ether_dhost;
    nd_mac_addr ether_shost;
    nd_uint16_t ether_length_type;
};


/*
 * Common code for printing Ethernet frames.
 *
 * It can handle Ethernet headers with extra tag information inserted
 * after the destination and source addresses, as is inserted by some
 * switch chips, and extra encapsulation header information before
 * printing Ethernet header information (such as a LANE ID for ATM LANE).
 */
static u_int
ether_common_print(ndo_t *ndo, void * infonode, const u_char *p, 
    u_int length, u_int caplen,
    void (*print_switch_tag)(ndo_t *ndo, const u_char *),
    u_int switch_tag_len,
    void (*print_encap_header)(ndo_t *ndo, const u_char *),
    const u_char *encap_header_arg)
{

    TC("Called { %s(%p, %p, %p, %u, %u, %p, %u, %p, %p)", __func__,
       ndo, infonode, p, length, caplen, print_switch_tag, switch_tag_len,
       print_encap_header, encap_header_arg);

    u_int orig_length;
    const struct ether_header *ehp;
    nd_dll_t *node = NULL;
    l1l2_node_t *su = NULL, *l1l2 = NULL;

    infonode_t *ifn = (infonode_t *)infonode;

    if (length < caplen)
    {
        TW("[length %u < caplen %u]((invalid))", length, caplen);
        return length;
    }
    if (caplen < ETHER_HDRLEN + switch_tag_len)
    {
        TW(" [|%s]", ndo->ndo_protocol);
        return caplen;
    }

    if (print_encap_header != NULL)
        (*print_encap_header)(ndo, encap_header_arg);

    orig_length = length;

    ehp = (const struct ether_header *)p;



    RUInt(ND_OK);
}


/*
 * Print an Ethernet frame.
 * This might be encapsulated within another frame; we might be passed
 * a pointer to a function that can print header information for that
 * frame's protocol, and an argument to pass to that function.
 *
 * FIXME: caplen can and should be derived from ndo->ndo_snapend and p.
 */
u_int ether_print(ndo_t *ndo, void *infonode,
                  const u_char *p, u_int length, u_int caplen,
                  void (*print_encap_header)(ndo_t *ndo, const u_char *),
                  const u_char *encap_header_arg)
{

    TI("Called { %s(%p, %p, %p, %u, %u, %p, %p)", __func__, ndo, 
        infonode, p, length, caplen, print_encap_header, encap_header_arg);

    ndo->ndo_protocol = "ether";
    u_int ret = ether_common_print(ndo, infonode, p, length, caplen, NULL, 0,
                              print_encap_header, encap_header_arg);

    RUInt(ret);
}


/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->len' is the length
 * of the packet off the wire, and 'h->caplen' is the number
 * of bytes actually captured.
 */
void ether_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{
    TI("Called { %s (%p, %p, %p)", __func__, infonode, h, p);

    infonode_t * ifn = (infonode_t *)infonode;
    ifn->typel2 = TYPE_L2_ETHER;

    ndo->ndo_protocol = "ether";
    ndo->ndo_ll_hdr_len += ether_print(ndo, infonode, p, h->len, h->caplen, NULL, NULL);

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
void netanalyzer_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
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
void netanalyzer_transparent_if_print(ndo_t *ndo, void *infonode,
                                      const struct pcap_pkthdr *h,
                                      const u_char *p)
{

    return ;
}