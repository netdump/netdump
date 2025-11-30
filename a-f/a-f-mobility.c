
#include "ndo.h"
#include "a-f-addrtoname.h"
#include "a-f-ip6.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"
#include "header.h"

#if 0

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Header  |  Hdr Ext Len  |   MH Type     |    Reserved    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 |                                                               |
 .                                                               .
 .                    Mobility Message Data                      .
 .                                                               .
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif



/* Mobility header */
struct ip6_mobility
{
    nd_uint8_t ip6m_pproto; /* following payload protocol (for PG) */
    nd_uint8_t ip6m_len;    /* length in units of 8 octets */
    nd_uint8_t ip6m_type;   /* message type */
    nd_uint8_t reserved;    /* reserved */
    nd_uint16_t ip6m_cksum; /* sum of IPv6 pseudo-header and MH */
    union
    {
        nd_uint16_t ip6m_un_data16[1]; /* type-specific field */
        nd_uint8_t ip6m_un_data8[2];   /* type-specific field */
    } ip6m_dataun;
};

#define ip6m_data16	ip6m_dataun.ip6m_un_data16
#define ip6m_data8	ip6m_dataun.ip6m_un_data8

#define IP6M_MINLEN	8

/* https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml */

/* message type */
#define IP6M_BINDING_REQUEST	0	/* Binding Refresh Request */
#define IP6M_HOME_TEST_INIT	1	/* Home Test Init */
#define IP6M_CAREOF_TEST_INIT	2	/* Care-of Test Init */
#define IP6M_HOME_TEST		3	/* Home Test */
#define IP6M_CAREOF_TEST	4	/* Care-of Test */
#define IP6M_BINDING_UPDATE	5	/* Binding Update */
#define IP6M_BINDING_ACK	6	/* Binding Acknowledgement */
#define IP6M_BINDING_ERROR	7	/* Binding Error */
#define IP6M_MAX		7

static const struct tok ip6m_str[] = {
    {IP6M_BINDING_REQUEST, "BRR"},
    {IP6M_HOME_TEST_INIT, "HoTI"},
    {IP6M_CAREOF_TEST_INIT, "CoTI"},
    {IP6M_HOME_TEST, "HoT"},
    {IP6M_CAREOF_TEST, "CoT"},
    {IP6M_BINDING_UPDATE, "BU"},
    {IP6M_BINDING_ACK, "BA"},
    {IP6M_BINDING_ERROR, "BE"},
    {0, NULL}
};

static const unsigned ip6m_hdrlen[IP6M_MAX + 1] = {
    IP6M_MINLEN,      /* IP6M_BINDING_REQUEST  */
    IP6M_MINLEN + 8,  /* IP6M_HOME_TEST_INIT   */
    IP6M_MINLEN + 8,  /* IP6M_CAREOF_TEST_INIT */
    IP6M_MINLEN + 16, /* IP6M_HOME_TEST        */
    IP6M_MINLEN + 16, /* IP6M_CAREOF_TEST      */
    IP6M_MINLEN + 4,  /* IP6M_BINDING_UPDATE   */
    IP6M_MINLEN + 4,  /* IP6M_BINDING_ACK      */
    IP6M_MINLEN + 16, /* IP6M_BINDING_ERROR    */
};

int mobility_print(ndo_t *ndo, void *infonode, void *_su, const u_char *bp, const char *bp2 _U_)
{

    TC("Called { %s(%p, %p, %p, %p)", __func__, ndo, infonode, bp, bp2);

    const struct ip6_mobility *mh;
    const u_char *ep;
    unsigned mhlen/*, hlen*/;
    uint8_t type;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)_su;

    ndo->ndo_protocol = "mobility";
    mh = (const struct ip6_mobility *)bp;

    /* 'ep' points to the end of available data. */
    ep = ndo->ndo_snapend;

    if (!ND_TTEST_1(mh->ip6m_len))
    {
        /*
         * There's not enough captured data to include the
         * mobility header length.
         *
         * Our caller expects us to return the length, however,
         * so return a value that will run to the end of the
         * captured data.
         *
         * XXX - "ip6_print()" doesn't do anything with the
         * returned length, however, as it breaks out of the
         * header-processing loop.
         */
        mhlen = (unsigned)(ep - bp);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Mobility field truncation (invalid)");
        goto trunc;
    }

    mhlen = (GET_U_1(mh->ip6m_len) + 1) << 3;
    type = GET_U_1(mh->ip6m_type);
    if (type <= IP6M_MAX && mhlen < ip6m_hdrlen[type])
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "(header length %u is too small for type %u)", mhlen, type);
        goto trunc;
    }

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_MOBILITY_NEXT_HEADER, 
        GET_U_1(mh->ip6m_pproto), 
        tok2str(ipproto_values, "unknown", GET_U_1(mh->ip6m_pproto)));

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_MOBILITY_LENGTH, GET_U_1(mh->ip6m_len));

    nd_filling_l2(ifn, su, 0, 1, 
        LAYER_3_IP6_MOBILITY_MSG_TYPE, type, tok2str(ip6m_str, "type-#%u", type));

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_MOBILITY_RESERVED, GET_U_1(mh->reserved));

    nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP6_MOBILITY_RESERVED, GET_BE_U_2(mh->ip6m_cksum));

    nd_filling_l2(ifn, su, 0, mhlen, LAYER_3_IP6_MOBILITY_MESSAGE_DATA);
    
    RInt(mhlen);
    
trunc:

    RInt(-1);
}