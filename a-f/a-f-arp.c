
#define ND_LONGJMP_FROM_TCHECK
#include "header.h"
#include "a-f-extract.h"
#include "a-f-ethertype.h"
#include "a-f-addrtoname.h"

/*

+-------------------+-------------------+-------------------+-------------------+
|   Hardware Type (ar_hrd, 2 bytes)     |   Protocol Type (ar_pro, 2 bytes)     |
+-------------------+-------------------+-------------------+-------------------+
|   HardLength (1B) |ProtocolLength (1B)|   Operation (ar_op, 2bytes)           |
+-------------------+-------------------+-------------------+-------------------+
|                   Sender Hardware Address (SHA, 6 bytes)                      |
+-------------------+-------------------+-------------------+-------------------+
|                   Sender Protocol Address (SPA, 4 bytes)                      |
+-------------------+-------------------+-------------------+-------------------+
|                   Target Hardware Address (THA, 6 bytes)                      |
+-------------------+-------------------+-------------------+-------------------+
|                   Target Protocol Address (TPA, 4 bytes)                      |
+-------------------+-------------------+-------------------+-------------------+

*/

/*
Frame 1: 60 bytes on wire
Ethernet II:
    Destination: ff:ff:ff:ff:ff:ff
    Source: 00:11:22:33:44:55
    Type: ARP (0x0806)
Address Resolution Protocol (request):
    Hardware type: Ethernet (1)
    Protocol type: IPv4 (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    Sender MAC address: 00:11:22:33:44:55
    Sender IP address: 192.168.1.10
    Target MAC address: 00:00:00:00:00:00
    Target IP address: 192.168.1.1

*/

#define LAYER_3_ARP_FORMAT              "%s"
#define LAYER_3_ARP_CONTENT             "Address Resolution Protocol: "
#define LAYER_3_ARP_HARDWARETYPE        "Hardware type: %s (%u)"
#define LAYER_3_ARP_PROTOCOLTYPE        "Protocol type: %s (0x%04x)"
#define LAYER_3_ARP_HARDWARESIZE        "Hardware size: %u"
#define LAYER_3_ARP_PROTOCOLSIZE        "Protocol size: %u"
#define LAYER_3_ARP_OPCODE              "Opcode: %s (%u)"
#define LAYER_3_ARP_S_MAC               "Sender MAC address: %s"
#define LAYER_3_ARP_S_IP                "Sender IP address: %s"
#define LAYER_3_ARP_T_MAC               "Target MAC address: %s"
#define LAYER_3_ARP_T_IP                "Target IP address: %s"

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct arp_pkthdr
{
    nd_uint16_t ar_hrd;      /* format of hardware address */
#define ARPHRD_ETHER 1       /* ethernet hardware format */
#define ARPHRD_IEEE802 6     /* token-ring hardware format */
#define ARPHRD_ARCNET 7      /* arcnet hardware format */
#define ARPHRD_FRELAY 15     /* frame relay hardware format */
#define ARPHRD_ATM2225 19    /* ATM (RFC 2225) */
#define ARPHRD_STRIP 23      /* Ricochet Starmode Radio hardware format */
#define ARPHRD_IEEE1394 24   /* IEEE 1394 (FireWire) hardware format */
#define ARPHRD_INFINIBAND 32 /* InfiniBand RFC 4391 */
    nd_uint16_t ar_pro;      /* format of protocol address */
    nd_uint8_t ar_hln;       /* length of hardware address */
    nd_uint8_t ar_pln;       /* length of protocol address */
    nd_uint16_t ar_op;       /* one of: */
#define ARPOP_REQUEST 1      /* request to resolve address */
#define ARPOP_REPLY 2        /* response to previous request */
#define ARPOP_REVREQUEST 3   /* request protocol address given hardware */
#define ARPOP_REVREPLY 4     /* response giving protocol address */
#define ARPOP_INVREQUEST 8   /* request to identify peer */
#define ARPOP_INVREPLY 9     /* response identifying peer */
#define ARPOP_NAK 10         /* NAK - only valid for ATM ARP */

/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
    nd_byte ar_sha[]; /* sender hardware address */
    nd_byte ar_spa[]; /* sender protocol address */
    nd_byte ar_tha[]; /* target hardware address */
    nd_byte ar_tpa[]; /* target protocol address */
#endif
#define ar_sha(ap) (((const u_char *)((ap) + 1)) + 0)
#define ar_spa(ap) (((const u_char *)((ap) + 1)) + GET_U_1((ap)->ar_hln))
#define ar_tha(ap) (((const u_char *)((ap) + 1)) + GET_U_1((ap)->ar_hln) + GET_U_1((ap)->ar_pln))
#define ar_tpa(ap) (((const u_char *)((ap) + 1)) + 2 * GET_U_1((ap)->ar_hln) + GET_U_1((ap)->ar_pln))
};

#define ARP_HDRLEN 8

#define HRD(ap) GET_BE_U_2((ap)->ar_hrd)
#define HRD_LEN(ap) GET_U_1((ap)->ar_hln)
#define PROTO_LEN(ap) GET_U_1((ap)->ar_pln)
#define OP(ap) GET_BE_U_2((ap)->ar_op)
#define PRO(ap) GET_BE_U_2((ap)->ar_pro)
#define SHA(ap) (ar_sha(ap))
#define SPA(ap) (ar_spa(ap))
#define THA(ap) (ar_tha(ap))
#define TPA(ap) (ar_tpa(ap))

static int
isnonzero(ndo_t *ndo, const u_char *a, size_t len)
{
    while (len > 0)
    {
        if (GET_U_1(a) != 0)
            return (1);
        a++;
        len--;
    }
    return (0);
}

static const struct tok arpop_values[] = {
    {ARPOP_REQUEST, "Request"},
    {ARPOP_REPLY, "Reply"},
    {ARPOP_REVREQUEST, "Reverse Request"},
    {ARPOP_REVREPLY, "Reverse Reply"},
    {ARPOP_INVREQUEST, "Inverse Request"},
    {ARPOP_INVREPLY, "Inverse Reply"},
    {ARPOP_NAK, "NACK Reply"},
    {0, NULL}
};

static const struct tok arphrd_values[] = {
    {ARPHRD_ETHER, "Ethernet"},
    {ARPHRD_IEEE802, "TokenRing"},
    {ARPHRD_ARCNET, "ArcNet"},
    {ARPHRD_FRELAY, "FrameRelay"},
    {ARPHRD_STRIP, "Strip"},
    {ARPHRD_IEEE1394, "IEEE 1394"},
    {ARPHRD_ATM2225, "ATM"},
    {ARPHRD_INFINIBAND, "InfiniBand"},
    {0, NULL}
};

void arp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length, u_int caplen)
{

    TC("Called { %s(%p, %p, %p, %u, %u)", __func__, ndo, infonode, bp, length, caplen);

    const struct arp_pkthdr *ap;
    u_short pro, hrd, op;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    ndo->ndo_protocol = "arp";

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    ap = (const struct arp_pkthdr *)bp;
    
    if (!ND_TTEST_LEN(ap, sizeof(*(ap))))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "length(%u) < %lu ((invalid))",
                 length, sizeof(struct arp_pkthdr));
        RVoid();
    }

    hrd = HRD(ap);
    pro = PRO(ap);
    op = OP(ap);

    if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Protocol type (0x%04x) invalid", pro);
        RVoid();
    }

    if (PROTO_LEN(ap) != 4)
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Protocol length (%u) invalid", PROTO_LEN(ap));
        RVoid();
    }

    if (HRD_LEN(ap) != 6)
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Hardware length (%u) invalid", HRD_LEN(ap));
        RVoid();
    }

    switch (hrd)
    {
        case ARPHRD_ARCNET:
        case ARPHRD_FRELAY:
        case ARPHRD_ATM2225:
        case ARPHRD_STRIP:
        case ARPHRD_IEEE1394:
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Hardware type %s (%u) not support", 
                tok2str(arphrd_values, "Unknown Hardware", hrd), hrd);
            RVoid();
        default:
            break;
    }

    if (!ND_TTEST_LEN(TPA(ap), PROTO_LEN(ap)))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "length(%u) < %lu ((invalid))",
                 length, sizeof(struct arp_pkthdr) + 2 * 6 + 2 * 4);
        RVoid();
    }

    su = nd_filling_l1(ifn, 0, LAYER_3_ARP_FORMAT, LAYER_3_ARP_CONTENT);

    nd_filling_l2(ifn, su, 0, 2, 
        LAYER_3_ARP_HARDWARETYPE, tok2str(arphrd_values, "Unknown Hardware", hrd), hrd);

    nd_filling_l2(ifn, su, 0, 2, 
        LAYER_3_ARP_PROTOCOLTYPE, tok2str(ethertype_values, "Unknown Protocol", pro), pro);

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_ARP_HARDWARESIZE, HRD_LEN(ap));

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_ARP_PROTOCOLSIZE, PROTO_LEN(ap));

    nd_filling_l2(ifn, su, 0, 2, 
        LAYER_3_ARP_OPCODE, tok2str(arpop_values, "Unknown", op), op);

    nd_filling_l2(ifn, su, 0, 6, 
        LAYER_3_ARP_S_MAC, 
        isnonzero(ndo, (const u_char *)SHA(ap), HRD_LEN(ap)) ? 
        get_etheraddr_string(ndo, (const u_char *)SHA(ap)) :
        "00:00:00:00:00:00"
    );

    nd_filling_l2(ifn, su, 0, 4, LAYER_3_ARP_S_IP, GET_IPADDR_STRING(SPA(ap)));

    nd_filling_l2(ifn, su, 0, 6, 
        LAYER_3_ARP_T_MAC, 
        isnonzero(ndo, (const u_char *)THA(ap), HRD_LEN(ap)) ?
        get_etheraddr_string(ndo, (const u_char *)THA(ap)) :
        "00:00:00:00:00:00"
    );

    nd_filling_l2(ifn, su, 0, 4, 
        LAYER_3_ARP_T_IP, GET_IPADDR_STRING(TPA(ap)));

    char sip[32] = {0}, tip[32] = {0};
    char smac[32] = {0}, tmac[32] = {0};

    snprintf(sip, 32, ipaddr_string(ndo, SPA(ap)));
    snprintf(tip, 32, ipaddr_string(ndo, TPA(ap)));
    snprintf(smac, 32, etheraddr_string(ndo, SHA(ap)));
    snprintf(tmac, 32, etheraddr_string(ndo, THA(ap)));

    switch (op) 
    {
        case ARPOP_REQUEST:
#define ARPOP_REQUEST_FMT       "who-has %s ? tell %s"
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, ARPOP_REQUEST_FMT, tip, sip);
            break;
        case ARPOP_REPLY:
#define ARPOP_REPLY_FMT         "%s is-at %s"
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, ARPOP_REPLY_FMT, sip, smac);
            break;
        case ARPOP_REVREQUEST:
#define ARPOP_REVREQUEST_FMT    "who-is %s tell %s"
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, ARPOP_REVREQUEST_FMT, tmac, smac);
            break;
        case ARPOP_REVREPLY:
#define ARPOP_REVREPLY_FMT      "%s at %s"
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, ARPOP_REVREPLY_FMT, tmac, tip);
            break;
        case ARPOP_INVREQUEST:
#define ARPOP_INVREQUEST_FMT    "who-is %s tell %s"
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, ARPOP_INVREQUEST_FMT, tmac, smac);
            break;
        case ARPOP_INVREPLY:
#define ARPOP_INVREPLY_FMT      "%s at %s"
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, ARPOP_INVREPLY_FMT, smac, sip);
            break;  
    }

    RVoid();
}
