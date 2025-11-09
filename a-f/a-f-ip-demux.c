

#include "ndo.h"
#include "a-f-addrtoname.h"
#include "a-f-extract.h"
#include "a-f-ip.h"
#include "a-f-ipproto.h"
#include "header.h"

void ip_demux_print(ndo_t *ndo, u_int index, void *infonode,
    const u_char *bp, u_int length, u_int ver, int fragmented, u_int ttl_hl,
                    uint8_t nh, const u_char *iph)
{

    TC("Called { %s(%p, %p, %u, %p, %u, %u, %d, %u, %u, %p)", __func__, ndo, 
        infonode, index, bp, length, ver, fragmented, ttl_hl, nh, iph);

    infonode_t *ifn = (infonode_t *)infonode;

    int advance;
    //const char *p_name;
    advance = 0;

again:
    
    switch (nh) {
        case IPPROTO_AH:
            if (!ND_TTEST_1(bp))
            {
                ndo->ndo_protocol = "ah";
                snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
                snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
                break;
            }
            nh = GET_U_1(bp);
            advance = ah_print(ndo, &index, infonode, bp);
            if (advance <= 0) {
                snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%d", length);
                snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", 
                    tok2str(ipproto_values, "unknown", nh));
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " data missing (invalid)");
                break;
            }
            bp += advance;
            length -= advance;
            goto again;
        case IPPROTO_ESP:
        {
            //esp_print(ndo, bp, length, iph, ver, fragmented, ttl_hl);
            /*
             * Either this has decrypted the payload and
             * printed it, in which case there's nothing more
             * to do, or it hasn't, in which case there's
             * nothing more to do.
             */
            break;
        }
        case IPPROTO_IPCOMP: 
        {
            ipcomp_print(ndo, &index, infonode, bp, length);
            /*
             * Either this has decompressed the payload and
             * printed it, in which case there's nothing more
             * to do, or it hasn't, in which case there's
             * nothing more to do.
             */
            break;
        }

        case IPPROTO_SCTP:
            //sctp_print(ndo, bp, iph, length);
            break;

        case IPPROTO_DCCP:
            //dccp_print(ndo, bp, iph, length);
            break;

        case IPPROTO_TCP:
            tcp_print(ndo, &index, infonode,bp, length, iph, fragmented);
            break;

        case IPPROTO_UDP:
            udp_print(ndo, &index, infonode, bp, length, iph, fragmented, ttl_hl);
            break;
        case IPPROTO_ICMP:
            if (ver == 4) {
                icmp_print(ndo, &index, infonode, bp, length, iph, fragmented);
            }
            else {
                snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
                snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", "icmp");
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " %s requires IPv4 (invalid)",
                    tok2str(ipproto_values,"unknown",nh)
                );
            }
            break;
        case IPPROTO_ICMPV6:
            if (ver == 6) {
                
            }
            else {
                snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
                snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", "icmp");
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " %s requires IPv4 (invalid)",
                    tok2str(ipproto_values,"unknown",nh)
                );
            }
            break;
    }

    RVoid();
}