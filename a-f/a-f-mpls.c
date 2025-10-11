
#include "header.h"
#include "a-f-mpls.h"
#include "a-f-extract.h"

#define LAYER_3_MPLS_FORMAT     "%s"
#define LAYER_3_MPLS_CONTENT    "Multiprotocol Label Switching"
#define LAYER_3_MPLS_LSE        "MPLS Label Stack Entry: Label=%d (%s), Exp=%d, S=%d, TTL=%d"

static const char *mpls_labelname[] = {
    /*0*/ 
    "IPv4 explicit NULL",
    "router alert",
    "IPv6 explicit NULL",
    "implicit NULL",
    "rsvd",
    /*5*/ 
    "rsvd",
    "rsvd",
    "rsvd",
    "rsvd",
    "rsvd",
    /*10*/ 
    "rsvd",
    "rsvd",
    "rsvd",
    "rsvd",
    "rsvd",
    /*15*/ 
    "rsvd",
};

enum mpls_packet_type
{
    PT_UNKNOWN,
    PT_IPV4,
    PT_IPV6,
    PT_OSI
};

/*
 * RFC3032: MPLS label stack encoding
 */

void mpls_print(ndo_t *ndo, u_int index, void *infonode,
                const u_char *bp, u_int length)
{
    TC("Called { %s(%p, %p, %u, %p, %u)", __func__, ndo, infonode, index, bp, length);

    const u_char *p;
    uint32_t label_entry;
    //uint16_t label_stack_depth = 0;
    uint8_t first;
    enum mpls_packet_type pt = PT_UNKNOWN;
    u_int rsdl = length;
    ndo->ndo_protocol = "mpls";
    p = bp;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    su = nd_get_fill_put_l1l2_node_level1(ifn, 0, 0, 0, LAYER_3_MPLS_FORMAT, LAYER_3_MPLS_CONTENT);

    do {
        if (length < sizeof(label_entry)) {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Insufficient remaining length (invalid)");
            goto invalid;
        }

        label_entry = GET_BE_U_4(p);

        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, index, index + 4 - 1, 
            LAYER_3_MPLS_LSE, MPLS_LABEL(label_entry), 
            MPLS_LABEL(label_entry) < sizeof(mpls_labelname) / sizeof(mpls_labelname[0]) ? mpls_labelname[MPLS_LABEL(label_entry)] : "",
            MPLS_TC(label_entry), MPLS_TTL(label_entry)
        );
        index = index + 4;
        p += sizeof(label_entry);
        length -= sizeof(label_entry);
    } while (!MPLS_STACK(label_entry));

    /*
	 * Try to figure out the packet type.
	 */
	switch (MPLS_LABEL(label_entry)) {
        case 0:	/* IPv4 explicit NULL label */
        case 3:	/* IPv4 implicit NULL label */
            pt = PT_IPV4;
            break;
        case 2: /* IPv6 explicit NULL label */
            pt = PT_IPV6;
            break;
        default:
		/*
		 * Generally there's no indication of protocol in MPLS label
		 * encoding.
		 *
		 * However, draft-hsmit-isis-aal5mux-00.txt describes a
		 * technique for encapsulating IS-IS and IP traffic on the
		 * same ATM virtual circuit; you look at the first payload
		 * byte to determine the network layer protocol, based on
		 * the fact that
		 *
		 *	1) the first byte of an IP header is 0x45-0x4f
		 *	   for IPv4 and 0x60-0x6f for IPv6;
		 *
		 *	2) the first byte of an OSI CLNP packet is 0x81,
		 *	   the first byte of an OSI ES-IS packet is 0x82,
		 *	   and the first byte of an OSI IS-IS packet is
		 *	   0x83;
		 *
		 * so the network layer protocol can be inferred from the
		 * first byte of the packet, if the protocol is one of the
		 * ones listed above.
		 *
		 * Cisco sends control-plane traffic MPLS-encapsulated in
		 * this fashion.
		 */
		if (length < 1) {
			/* nothing to print */
            snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", rsdl);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "mpls packet type unknow, length < 1");
            RVoid();
        }
		first = GET_U_1(p);
		pt =
			(first >= 0x45 && first <= 0x4f) ? PT_IPV4 :
			(first >= 0x60 && first <= 0x6f) ? PT_IPV6 :
			(first >= 0x81 && first <= 0x83) ? PT_OSI :
			/* ok bail out - we did not figure out what it is*/
			PT_UNKNOWN;
    }

    /*
     * Print the payload.
     */
    switch (pt)
    {
        case PT_UNKNOWN:
            snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", rsdl);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "mpls packet type unknow");
            break;

        case PT_IPV4:
            ip_print(ndo, index, infonode, p, length);
            break;

        case PT_IPV6:
            ip6_print(ndo, index, infonode, p, length);
            break;

        case PT_OSI:
            //isoclns_print(ndo, p, length);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Not supported yet");
            goto invalid;
            break;
    }
    RVoid();

invalid:

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", rsdl);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    RVoid();
}