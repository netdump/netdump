
#include "ndo.h"
#include "a-f-addrtoname.h"
#include "a-f-ip6.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"
#include "header.h"

const char * ip6_opt_type_str(unsigned int type) 
{
    if (type == IP6OPT_PAD1)
        return "PAD1";
    if (type == IP6OPT_PADN)
        return "PADN";
    if (type == IP6OPT_ROUTER_ALERT)
        return "ROUTER_ALERT";
    if (type == IP6OPT_JUMBO)
        return "JUMBO";
    if (type == IP6OPT_HOME_ADDRESS)
        return "HOME_ADDRESS";

    return "";
}

static int
ip6_sopt_print(ndo_t *ndo, void *infonode, l1l2_node_t *su, const char *nhinfo, 
            const u_char *bp, int len)
{
    int i;
    int optlen;
    infonode_t *ifn = (infonode_t *)infonode;

    for (i = 0; i < len; i += optlen) 
    {
        if (GET_U_1(bp + i) == IP6OPT_PAD1)
        {
            optlen = 1;
        }
        else
        {
            if (i + 1 < len) 
            {
                optlen = GET_U_1(bp + i + 1) + 2;
            }
            else
            {
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                         "%s Options %s (%u) truncated (invalid)", nhinfo,
                         ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i)
                );
                goto trunc;
            }
        }

        if (i + optlen > len) 
        {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                     "%s Options %s (%u) truncated (invalid)", nhinfo, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i)
            );
            goto trunc;
        }

        switch (GET_U_1(bp + i))
        {
            case IP6OPT_PAD1:
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                break;
            case IP6OPT_PADN:
                if (len - i < IP6OPT_MINLEN)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                        "%s Options %s (%u) truncated (invalid)", nhinfo,
                        ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i)
                    );
                    goto trunc;
                }
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_LENGTH, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), GET_U_1(bp + i + 1), nhinfo);
                
                nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_PADN_VAL, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                break;
            default:
                if (len - i < IP6OPT_MINLEN)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) truncated (invalid)", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i));
                    goto trunc;
                }
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_LENGTH, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), GET_U_1(bp + i + 1), nhinfo);
                
                nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_OTHER_VAL, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                break;
        }
    }


trunc:
    return -1;
}

// Options Type Length Value [TLV]

static int ip6_opt_process(ndo_t *ndo, void *infonode, l1l2_node_t *su, const char * nhinfo, 
            const u_char *bp, int len, int *found_jumbop, uint32_t *payload_len)
{

    int i;
    int optlen = 0;
    int found_jumbo = 0;
    uint32_t jumbolen = 0;
    infonode_t *ifn = (infonode_t *)infonode;

    if (len == 0) 
        return 0;

    for (i = 0; i < len; i += optlen) 
    {
        if (GET_U_1(bp + i) == IP6OPT_PAD1) 
        {
            optlen = 1;
        }
        else 
        {
            if (i + 1 < len) 
            {
                optlen = GET_U_1(bp + i + 1) + 2;
            }
            else 
            {
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                         "%s Options %s (%u) truncated (invalid)", nhinfo,
                         ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i)
                );
                goto trunc;
            }
        }

        if (i + optlen > len) 
        {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                     "%s Options %s (%u) truncated (invalid)", nhinfo, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i)
            );
            goto trunc;
        }

        switch (GET_U_1(bp + i)) 
        {
            case IP6OPT_PAD1:
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo
                );
                break;
            case IP6OPT_PADN:
                if (len - i < IP6OPT_MINLEN)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                        "%s Options %s (%u) truncated (invalid)", nhinfo,
                        ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i)
                    );
                    goto trunc;
                }
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);

                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_LENGTH, 
                    ip6_opt_type_str(GET_U_1(bp + i)),  GET_U_1(bp + i), GET_U_1(bp + i + 1), nhinfo);

                nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_PADN_VAL, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                break;
            case IP6OPT_ROUTER_ALERT:
                if (len - i < IP6OPT_RTALERT_LEN)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) truncated (invalid)", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i)
                    );
                    goto trunc;
                }
                if (GET_U_1(bp + i + 1) != IP6OPT_RTALERT_LEN - 2)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) Invalid Length", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i));
                    goto trunc;
                }
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_LENGTH, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), GET_U_1(bp + i + 1), nhinfo);

                nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_VALUE_HEX, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), GET_BE_U_2(bp + i + 2), nhinfo);
                
                break;
            case IP6OPT_JUMBO:
                if (len - i < IP6OPT_JUMBO_LEN)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) truncated (invalid)", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i));
                    goto trunc;
                }
                if (GET_U_1(bp + i + 1) != IP6OPT_JUMBO_LEN - 2)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) Invalid Length", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i));
                    goto trunc;
                }
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_LENGTH, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), GET_U_1(bp + i + 1), nhinfo);
                
                jumbolen = GET_BE_U_4(bp + i + 2);
                if (found_jumbo)
                {
                    /* More than one Jumbo Payload option */
                    nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_JUMBO_VAL, 
                        ip6_opt_type_str(GET_U_1(bp + i)),
                        GET_U_1(bp + i), jumbolen, "- already seen", nhinfo);
                }
                else 
                {
                    found_jumbo = 1;
                    if (payload_len == NULL)
                    {
                        /* Not a hop-by-hop option - not valid */
                        nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_JUMBO_VAL, 
                            ip6_opt_type_str(GET_U_1(bp + i)),
                            GET_U_1(bp + i), jumbolen, "- not a hop-by-hop option", nhinfo);
                    }
                    else if (*payload_len != 0)
                    {
                        /* Payload length was non-zero - not valid */
                        nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_JUMBO_VAL, 
                            ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), 
                            jumbolen, "- payload len != 0", nhinfo);
                    }
                    else 
                    {
                        if (jumbolen < 65536)
                        {
                            /*
                             * This is a hop-by-hop option, and Payload length
                             * was zero in the IPv6 header.
                             */
                            nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_JUMBO_VAL, 
                                ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), jumbolen, "- < 65536", nhinfo);
                        }
                        else 
                        {
                            /* OK, this is valid */
                            *found_jumbop = 1;
                            *payload_len = jumbolen;
                            nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_JUMBO_VAL, 
                                ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), jumbolen, "", nhinfo);
                        }
                    }
                }
                break;
            case IP6OPT_HOME_ADDRESS:
                if (len - i < IP6OPT_HOMEADDR_MINLEN)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) truncated (invalid)", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i));
                    goto trunc;
                }
                if (GET_U_1(bp + i + 1) < IP6OPT_HOMEADDR_MINLEN - 2)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) Invalid Length", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i));
                    goto trunc;
                }
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_LENGTH, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), GET_U_1(bp + i + 1), nhinfo);
                
                nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_HA_VAL_STR, 
                    ip6_opt_type_str(GET_U_1(bp + i)), 
                    GET_U_1(bp + i), GET_IP6ADDR_STRING(bp + i + 2), nhinfo);
                
                if (GET_U_1(bp + i + 1) > IP6OPT_HOMEADDR_MINLEN - 2)
                {
                    if (ip6_sopt_print(ndo, infonode, su, nhinfo, 
                            bp + i + IP6OPT_HOMEADDR_MINLEN, (optlen - IP6OPT_HOMEADDR_MINLEN)) == -1)
                    {
                        goto trunc;
                    }
                }
                break;
            default:
                if (len - i < IP6OPT_MINLEN)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "%s Options %s (%u) truncated (invalid)", nhinfo,
                             ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i));
                    goto trunc;
                }
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_TYPE, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_OPT_LENGTH, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), GET_U_1(bp + i + 1), nhinfo);
                
                nd_filling_l2(ifn, su, 0, optlen - 2, LAYER_3_IP6_OPT_OTHER_VAL, 
                    ip6_opt_type_str(GET_U_1(bp + i)), GET_U_1(bp + i), nhinfo);
                
                break;
        }
    }

    return 0;

trunc:
    return -1;
}

int hbhopt_process(ndo_t *ndo, void *infonode, void *_su, const u_char *bp, 
                    int *found_jumbo, uint32_t *jumbolen)
{

    TC("Called { %s(%p, %p, %p, %p)", __func__, ndo, infonode, found_jumbo, jumbolen);

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)_su;

    const struct ip6_hbh *dp = (const struct ip6_hbh *)bp;
    u_int hbhlen = 0;

    ndo->ndo_protocol = "hbhopt";
    hbhlen = (GET_U_1(dp->ip6h_len) + 1) << 3;

    if (!ND_TTEST_LEN(dp, hbhlen)) 
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Hop-by-Hop truncated (invalid)");
        goto trunc;
    }

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_HOP_BY_HOP_NXT_HEARDER, 
        GET_U_1(dp->ip6h_nxt), tok2str(ipproto_values, "unknown", GET_U_1(dp->ip6h_nxt)));

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_HOP_BY_HOP_LENGTH, GET_U_1(dp->ip6h_len));

    if (ip6_opt_process(
        ndo, infonode, su, "Hop-By-Hop",
        (const u_char *)dp + sizeof(*dp), 
        hbhlen - sizeof(*dp), found_jumbo, jumbolen) == -1)
    {
        goto trunc;
    }

    return hbhlen;

trunc:

    RInt(-1);
}

int dstopt_process(ndo_t *ndo, void *infonode, void *_su, const u_char *bp)
{

    TC("Called { %s(%p, %p, %p)", __func__, ndo, infonode, _su);

    const struct ip6_dest *dp = (const struct ip6_dest *)bp;
    u_int dstoptlen = 0;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)_su;

    ndo->ndo_protocol = "dstopt";
    dstoptlen = (GET_U_1(dp->ip6d_len) + 1) << 3;

    if (!ND_TTEST_LEN(dp, dstoptlen))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Destination truncated (invalid)");
        goto trunc;
    }

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_DEST_NXT_HEARDER, 
        GET_U_1(dp->ip6d_nxt), tok2str(ipproto_values, "unknown", GET_U_1(dp->ip6d_nxt)));

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_DEST_LENGTH, GET_U_1(dp->ip6d_len));

    if (ip6_opt_process(
            ndo, infonode, su, "Destination", (const u_char *)dp + sizeof(*dp),
            dstoptlen - sizeof(*dp), NULL, NULL) == -1)
    {
        goto trunc;
    }

    return dstoptlen;
trunc:
    RInt(-1);
}