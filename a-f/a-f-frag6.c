
#include "ndo.h"
#include "a-f-addrtoname.h"
#include "a-f-ip6.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"
#include "header.h"

int frag6_print(ndo_t *ndo, void *infonode, void *_su, const u_char *bp, const char *bp2)
{

    TC("Called { %s(%p, %p, %p, %p)", __func__, ndo, infonode, bp, bp2);

    const struct ip6_frag *dp;
    //const struct ip6_hdr *ip6;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)_su;

    ndo->ndo_protocol = "frag6";
    dp = (const struct ip6_frag *)bp;
    //ip6 = (const struct ip6_hdr *)bp2;

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_FRAG6_NEXT_HEAD, 
        GET_U_1(dp->ip6f_nxt), tok2str(ipproto_values, "unknown", GET_U_1(dp->ip6f_nxt)));
    
    nd_filling_l2(ifn, su, 0, 1, 
        LAYER_3_IP6_FRAG6_RESERVED, GET_U_1(dp->ip6f_reserved));

    nd_filling_l2(ifn, su, 0, 2, 
        LAYER_3_IP6_FRAG6_OFFSET_FLAG, (GET_BE_U_2(dp->ip6f_offlg) & IP6F_OFF_MASK),
        (GET_BE_U_2(dp->ip6f_offlg) & IP6F_RESERVED_MASK),
        (GET_BE_U_2(dp->ip6f_offlg) & IP6F_MORE_FRAG)
    );

    nd_filling_l2(ifn, su, 0, 4, LAYER_3_IP6_FRAG6_IDENT, GET_BE_U_4(dp->ip6f_ident));

    /* it is meaningless to decode non-first fragment */
    if ((GET_BE_U_2(dp->ip6f_offlg) & IP6F_OFF_MASK) != 0)
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "non-first fragment");
        RInt(-1);
    }

    RLong((sizeof(struct ip6_frag)));
}