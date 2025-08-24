
#include "ndo.h"
#include "a-f-addrtoname.h"
#include "a-f-ip6.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"
#include "header.h"

int rt6_print(ndo_t *ndo, void *infonode, void *_su, u_int *index,
              const u_char *bp, const char *bp2)
{

    TC("Called { %s(%p, %p, %u, %p, %p)", __func__, ndo, infonode, *index, bp, bp2);

    const struct ip6_rthdr *dp;
    const struct ip6_rthdr0 *dp0;
    const struct ip6_srh *srh;
    u_int i, len, type;
    const u_char *p;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)_su;

    ndo->ndo_protocol = "rt6";

    dp = (const struct ip6_rthdr *)bp;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index, 
        LAYER_3_IP6_FRAG6_NEXT_HEAD, 
        GET_U_1(dp->ip6r_nxt), 
        tok2str(ipproto_values, "unknown", GET_U_1(dp->ip6r_nxt)));
    *index = *index + 1;

    len = GET_U_1(dp->ip6r_len);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index, 
        LAYER_3_IP6_RTHDR_LENGTH, len);
    *index = *index + 1;

    type = GET_U_1(dp->ip6r_type);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index, 
        LAYER_3_IP6_RTHDR_TYPE, GET_U_1(dp->ip6r_type));
    *index = *index + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index, 
        LAYER_3_IP6_RTHDR_SEGLEFT, GET_U_1(dp->ip6r_segleft));
    *index = *index + 1;

    switch (type) 
    {
        case IPV6_RTHDR_TYPE_0:
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Deprecated types (invalid)");
            goto invalid;
            break;
        case IPV6_RTHDR_TYPE_2:
            dp0 = (const struct ip6_rthdr0 *)dp;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index + 4 - 1, 
                LAYER_3_IP6_RTHDR_RSV, GET_BE_U_4(dp0->ip6r0_reserved));
            *index = *index + 4;
            if ((len % 2) == 1) {
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Illegal field value %u (invalid)", len);
                goto invalid;
            }
            p = (const u_char *)dp0->ip6r0_addr;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index + 16 - 1, 
                LAYER_3_IP6_RTHDR_HOA, GET_IP6ADDR_STRING(p));
            *index = *index + 16;
            RInt(((GET_U_1(dp0->ip6r0_len) + 1) << 3));
            break;
        case IPV6_RTHDR_TYPE_4:
            srh = (const struct ip6_srh *)dp;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index, 
                LAYER_3_IP6_RTHDR_SRH_LAST_ENTRY, GET_U_1(srh->srh_last_ent));
            *index = *index + 1;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index, 
                LAYER_3_IP6_RTHDR_SRH_FLAGS, GET_U_1(srh->srh_flags));
            *index = *index + 1;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index + 2 - 1, 
                LAYER_3_IP6_RTHDR_SRH_TAG, GET_BE_U_2(srh->srh_tag));
            *index = *index + 2;
            len >>= 1;
            p = (const u_char *)srh->srh_segments;
            for (i = 0; i < len; i++) {
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index + 16 - 1, 
                    LAYER_3_IP6_RTHDR_SRH_SID, i, GET_IP6ADDR_STRING(p));
                *index = *index + 16;
                p += 16;
            }
            RInt((GET_U_1(srh->srh_len) + 1) << 3);
            break;
        default:
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Unknown types (invalid)");
            goto invalid;
    }

invalid:

    RInt(-1);
}