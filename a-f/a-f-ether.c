
#include "header.h"
#include "a-f-extract.h"
#include "a-f-ethertype.h"
#include "a-f-addrtoname.h"

/*
 * Length of an Ethernet header; note that some compilers may pad
 * "struct ether_header" to a multiple of 4 bytes, for example, so
 * "sizeof (struct ether_header)" may not give the right answer.
 */
#define ETHER_HDRLEN 14

#define LAYER_2_FORMAT                      "%s"
#define LAYER_2_CONTENT                     "Ethernet II: "
#define LAYER_2_SOURCE_MAC_FORMAT           "source mac: %s"
#define LAYER_2_DESTINATION_MAC_FORMAT      "destination mac: %s"
#define LAYER_2_ETHERTYPE_FORMAT            "ether type: %s"
#define LAYER_2_ETHERTYPE_IEEE8021Q_FMT     "pcp: %d, dei: %d, vlanid: %d"

const struct tok ethertype_values[] = {
    {ETHERTYPE_IP, "IPv4"},
    {ETHERTYPE_MPLS, "MPLS unicast"},
    {ETHERTYPE_MPLS_MULTI, "MPLS multicast"},
    {ETHERTYPE_IPV6, "IPv6"},
    {ETHERTYPE_8021Q, "802.1Q"},
    {ETHERTYPE_8021Q9100, "802.1Q-9100"},
    {ETHERTYPE_8021QinQ, "802.1Q-QinQ"},
    {ETHERTYPE_8021Q9200, "802.1Q-9200"},
    {ETHERTYPE_MACSEC, "802.1AE MACsec"},
    {ETHERTYPE_VMAN, "VMAN"},
    {ETHERTYPE_PUP, "PUP"},
    {ETHERTYPE_ARP, "ARP"},
    {ETHERTYPE_REVARP, "Reverse ARP"},
    {ETHERTYPE_NS, "NS"},
    {ETHERTYPE_SPRITE, "Sprite"},
    {ETHERTYPE_TRAIL, "Trail"},
    {ETHERTYPE_MOPDL, "MOP DL"},
    {ETHERTYPE_MOPRC, "MOP RC"},
    {ETHERTYPE_DN, "DN"},
    {ETHERTYPE_LAT, "LAT"},
    {ETHERTYPE_SCA, "SCA"},
    {ETHERTYPE_TEB, "TEB"},
    {ETHERTYPE_LANBRIDGE, "Lanbridge"},
    {ETHERTYPE_DECDNS, "DEC DNS"},
    {ETHERTYPE_DECDTS, "DEC DTS"},
    {ETHERTYPE_VEXP, "VEXP"},
    {ETHERTYPE_VPROD, "VPROD"},
    {ETHERTYPE_ATALK, "Appletalk"},
    {ETHERTYPE_AARP, "Appletalk ARP"},
    {ETHERTYPE_IPX, "IPX"},
    {ETHERTYPE_PPP, "PPP"},
    {ETHERTYPE_MPCP, "MPCP"},
    {ETHERTYPE_SLOW, "Slow Protocols"},
    {ETHERTYPE_PPPOED, "PPPoE D"},
    {ETHERTYPE_PPPOES, "PPPoE S"},
    {ETHERTYPE_EAPOL, "EAPOL"},
    {ETHERTYPE_REALTEK, "Realtek protocols"},
    {ETHERTYPE_MS_NLB_HB, "MS NLB heartbeat"},
    {ETHERTYPE_JUMBO, "Jumbo"},
    {ETHERTYPE_NSH, "NSH"},
    {ETHERTYPE_LOOPBACK, "Loopback"},
    {ETHERTYPE_ISO, "OSI"},
    {ETHERTYPE_GRE_ISO, "GRE-OSI"},
    {ETHERTYPE_CFM_OLD, "CFM (old)"},
    {ETHERTYPE_CFM, "CFM"},
    {ETHERTYPE_IEEE1905_1, "IEEE1905.1"},
    {ETHERTYPE_LLDP, "LLDP"},
    {ETHERTYPE_TIPC, "TIPC"},
    {ETHERTYPE_GEONET_OLD, "GeoNet (old)"},
    {ETHERTYPE_GEONET, "GeoNet"},
    {ETHERTYPE_CALM_FAST, "CALM FAST"},
    {ETHERTYPE_AOE, "AoE"},
    {ETHERTYPE_PTP, "PTP"},
    {ETHERTYPE_ARISTA, "Arista Vendor Specific Protocol"},
    {0, NULL}
};

/*
 * Structure of an Ethernet header.
 */
struct ether_header
{
    nd_mac_addr ether_dhost;
    nd_mac_addr ether_shost;
    nd_uint16_t ether_length_type;
};

static inline void fill_ether_type(uint16_t type, char *roomage)
{
    snprintf(roomage, L1L2NODE_CONTENT_LENGTH, "Ethertype: %s (0x%04x)",
             tok2str(ethertype_values, "Unknown Ethertype", type), type);
    return ;
}

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

    u_int index = 0;
    u_int hdrlen;
    u_short length_type;
    const struct ether_header *ehp;
    struct lladdr_info src, dst;
    char buffer[L1L2NODE_CONTENT_LENGTH] = {0};
    l1l2_node_t *su = NULL;

    infonode_t *ifn = (infonode_t *)infonode;

    if (length < caplen)
    {
        TW("[length %u < caplen %u]((invalid))", length, caplen);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[length %u < caplen %u]((invalid))", 
            length, caplen);
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        return length;
    }

    if (caplen < ETHER_HDRLEN + switch_tag_len)
    {
        TW(" [|%s]", ndo->ndo_protocol);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[caplen %u < %u]((invalid))",
                 caplen, (ETHER_HDRLEN + switch_tag_len));
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        return caplen;
    }

    if (print_encap_header != NULL)
        (*print_encap_header)(ndo, encap_header_arg);

    ehp = (const struct ether_header *)p;

    src.addr = ehp->ether_shost;
    src.addr_string = etheraddr_string;
    dst.addr = ehp->ether_dhost;
    dst.addr_string = etheraddr_string;

    su = nd_get_fill_put_l1l2_node_level1(ifn, 0, 0, 0, LAYER_2_FORMAT, LAYER_2_CONTENT);

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, index, (index + MAC_ADDR_LEN - 1), 
        LAYER_2_DESTINATION_MAC_FORMAT, 
        get_etheraddr_string(ndo, (const uint8_t *)ehp->ether_dhost)
    );

    index += MAC_ADDR_LEN;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, index, (index + MAC_ADDR_LEN - 1), 
        LAYER_2_SOURCE_MAC_FORMAT, 
        get_etheraddr_string(ndo, (const uint8_t *)ehp->ether_shost)
    );

    index += MAC_ADDR_LEN;

    length -= 2 * MAC_ADDR_LEN;
    caplen -= 2 * MAC_ADDR_LEN;
    p += 2 * MAC_ADDR_LEN;
    hdrlen = 2 * MAC_ADDR_LEN;

    #if 0
    /*
     * Print the switch tag, if we have one, and skip past it.
     */
    if (print_switch_tag != NULL)
        (*print_switch_tag)(ndo, p);

    length -= switch_tag_len;
    caplen -= switch_tag_len;
    p += switch_tag_len;
    hdrlen += switch_tag_len;
    index += switch_tag_len;
    #endif

    /*
     * Get the length/type field, skip past it, and print it
     * if we're printing the link-layer header.
     */
    length_type = GET_BE_U_2(p);

    length -= 2;
    caplen -= 2;
    p += 2;
    hdrlen += 2;

    memset(buffer, 0, L1L2NODE_CONTENT_LENGTH);
    fill_ether_type(length_type, buffer);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, index, (index + 2 - 1), LAYER_2_ETHERTYPE_FORMAT, buffer);

    index += 2;

    /*
     * Process 802.1AE MACsec headers.
     */
    if (length_type == ETHERTYPE_MACSEC)
    {
        /*
         * MACsec, aka IEEE 802.1AE-2006
         * Print the header, and try to print the payload if it's not encrypted
         */
        int ret = macsec_print(ndo, &p, infonode, su, &index, &length, &caplen, &hdrlen);
        if (ret == 0) {
            /* Payload is encrypted; print it as raw data. */
            snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
            snprintf(ifn->srcaddr, INFONODE_ADDR_LENGTH, "%s", get_etheraddr_string(ndo, (const uint8_t *)ehp->ether_shost));
            snprintf(ifn->dstaddr, INFONODE_ADDR_LENGTH, "%s", get_etheraddr_string(ndo, (const uint8_t *)ehp->ether_dhost));
            RUInt(hdrlen);
        }
        else if (ret > 0) {
            /* Problem printing the header; just quit. */
            snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
            RInt(ret);
        }
        else {
            /*
             * Keep processing type/length fields.
             */
            if (caplen < 2 || length < 2) 
            {
                snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
                #if 0
                memset(buffer, 0, L1L2NODE_CONTENT_LENGTH);
                fill_etheraddr_string(ndo, (const uint8_t *)ehp->ether_shost, buffer);
                memcpy(ifn->srcaddr, buffer, INFONODE_ADDR_LENGTH);
                memset(buffer, 0, L1L2NODE_CONTENT_LENGTH);
                fill_etheraddr_string(ndo, (const uint8_t *)ehp->ether_dhost, buffer);
                memcpy(ifn->dstaddr, buffer, INFONODE_ADDR_LENGTH);
                #endif
                snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "macsec");
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "remaining length < 2 ((invalid))");
                goto invalid;
            }
            length_type = GET_BE_U_2(p);
            memset(buffer, 0, L1L2NODE_CONTENT_LENGTH);
            fill_ether_type(length_type, buffer);
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, index, (index + 2 - 1), LAYER_2_ETHERTYPE_FORMAT, buffer);
            length -= 2;
            caplen -= 2;
            p += 2;
            hdrlen += 2;
            index += 2;
        }
    }

    while (
        length_type == ETHERTYPE_8021Q || length_type == ETHERTYPE_8021Q9100 ||
        length_type == ETHERTYPE_8021Q9200 || length_type == ETHERTYPE_8021QinQ
    )
    {
        /*
         * It has a VLAN tag.
         * Print VLAN information, and then go back and process
         * the enclosed type field.
         */
        if (caplen < 4)
        {
            ndo->ndo_protocol = "vlan";
            snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "remaining caplen < 4 ((invalid))");
            return hdrlen + caplen;
        }
        if (length < 4)
        {
            ndo->ndo_protocol = "vlan";
            snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "remaining length < 4 ((invalid))");
            return hdrlen + length;
        }

        uint16_t tag = GET_BE_U_2(p);
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, index, (index + 2 - 1), LAYER_2_ETHERTYPE_IEEE8021Q_FMT, 
            ((tag >> 13) & 0x07), ((tag >> 12) & 0x01), (tag & 0x0FFF));
        index += 2;

        length_type = GET_BE_U_2((p + 2));
        memset(buffer, 0, L1L2NODE_CONTENT_LENGTH);
        fill_ether_type(length_type, buffer);
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, index, (index + 2 - 1), LAYER_2_ETHERTYPE_FORMAT, buffer);

        p += 4;
        length -= 4;
        caplen -= 4;
        hdrlen += 4;
    }

    if (length_type <= MAX_ETHERNET_LENGTH_VAL ||
        length_type == ETHERTYPE_JUMBO ||
        length_type == ETHERTYPE_ARISTA
    ) 
    {
        memset(buffer, 0, L1L2NODE_CONTENT_LENGTH);
        fill_ether_type(length_type, buffer);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "%s is not supported", buffer);
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        goto invalid;
    }

    if (ethertype_print(ndo, index, infonode, length_type, p, length, caplen, &src, &dst) == 0)
    {
        memset(buffer, 0, L1L2NODE_CONTENT_LENGTH);
        fill_ether_type(length_type, buffer);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "%s is not supported", buffer);
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
    }

invalid:
    RUInt(hdrlen);
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

/*
 * Prints the packet payload, given an Ethernet type code for the payload's
 * protocol.
 *
 * Returns non-zero if it can do so, zero if the ethertype is unknown.
 */

int ethertype_print(ndo_t *ndo, u_int index, void *infonode,
        u_short ether_type, const u_char *p, u_int length, u_int caplen,
        const struct lladdr_info *src, const struct lladdr_info *dst
    )
{

    infonode_t *ifn = (infonode_t *)infonode;

    switch (ether_type)
    {
        case ETHERTYPE_IP:
            ip_print(ndo, index, infonode, p, length);
            return (1);

        case ETHERTYPE_IPV6:
            ip6_print(ndo, index, infonode, p, length);
            return (1);

        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:
            snprintf(ifn->srcaddr, INFONODE_ADDR_LENGTH, "%s", src->addr_string(ndo, (const uint8_t *)src->addr));
            snprintf(ifn->dstaddr, INFONODE_ADDR_LENGTH, "%s", dst->addr_string(ndo, (const uint8_t *)dst->addr));
            arp_print(ndo, index, infonode, p, length, caplen);
            return (1);
        
        case ETHERTYPE_PPPOED:
        case ETHERTYPE_PPPOES:
            //pppoe_print(ndo, p, length);
            return (1);

        case ETHERTYPE_EAPOL:
            snprintf(ifn->srcaddr, INFONODE_ADDR_LENGTH, "%s", src->addr_string(ndo, (const uint8_t *)src->addr));
            snprintf(ifn->dstaddr, INFONODE_ADDR_LENGTH, "%s", dst->addr_string(ndo, (const uint8_t *)dst->addr));
            eapol_print(ndo, index, infonode, p, length);
            return (1);

        case ETHERTYPE_SLOW:
            //slow_print(ndo, p, length);
            return (1);

        case ETHERTYPE_LLDP:
            //lldp_print(ndo, p, length);
            return (1);

        case ETHERTYPE_MPLS:
        case ETHERTYPE_MPLS_MULTI:
            mpls_print(ndo, index, infonode, p, length);
            return (1);

        case ETHERTYPE_PTP:
            ptp_print(ndo, index, infonode, p, length);
            return (1);

        case ETHERTYPE_LAT:
        case ETHERTYPE_SCA:
        case ETHERTYPE_MOPRC:
        case ETHERTYPE_MOPDL:
        case ETHERTYPE_IEEE1905_1:
        case ETHERTYPE_DN:
        case ETHERTYPE_ATALK:
        case ETHERTYPE_AARP:
        case ETHERTYPE_IPX:
        case ETHERTYPE_ISO:
        case ETHERTYPE_PPPOED2:
        case ETHERTYPE_PPPOES2:
        case ETHERTYPE_REALTEK:
        case ETHERTYPE_PPP:
        case ETHERTYPE_MPCP:
        case ETHERTYPE_CFM:
        case ETHERTYPE_CFM_OLD:
        case ETHERTYPE_NSH:
        case ETHERTYPE_LOOPBACK:
        case ETHERTYPE_TIPC:
        case ETHERTYPE_MS_NLB_HB:
        case ETHERTYPE_GEONET_OLD:
        case ETHERTYPE_GEONET:
        case ETHERTYPE_CALM_FAST:
        case ETHERTYPE_AOE:
            /* default_print for now */
        default:
            return (0);
    }
}