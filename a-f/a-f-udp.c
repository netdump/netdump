
#include "ndo.h"
#include "header.h"
#include "a-f-ip.h"
#include "a-f-ip6.h"
#include "a-f-udp.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"

#define LAYER_4_UDP_CONTENT             "User Datagram Protocol (udp): "
#define LAYER_4_UDP_SPORT               "source port: %hu"
#define LAYER_4_UDP_DPORT               "destination port: %hu"
#define LAYER_4_UDP_ULEN                "udp length: %u"
#define LAYER_4_UDP_CHECKSUM            "udp checksum: 0x%04x"
#define LAYER_4_UDP_NO_CHECKSUM         "udp checksum: 0x%04x (no cksum)"
#define LAYER_4_UDP_BAD_CHECKSUM        "udp checksum: 0x%04x (bad) -> 0x%04x!"

static uint16_t 
udp_cksum(ndo_t *ndo, const struct ip *ip, const struct udphdr *up, u_int len)
{
    return nextproto4_cksum(ndo, ip, (const uint8_t *)(const void *)up, len, len,
                            IPPROTO_UDP);
}

static uint16_t 
udp6_cksum(ndo_t *ndo, const struct ip6_hdr *ip6, const struct udphdr *up, u_int len)
{
    return nextproto6_cksum(ndo, ip6, (const uint8_t *)(const void *)up, len, len,
                            IPPROTO_UDP);
}

static void udpipaddr_print(ndo_t *ndo, void *infonode, const struct ip *ip, int sport, int dport)
{

    TC("Called { %s(%p, %p, %p, %d, %d)", __func__, ndo, infonode, ip, sport, dport);

    if (sport == -1 || dport == -1) {
        RVoid();
    }

    infonode_t *ifn = (infonode_t *)infonode;

    snprintf((ifn->srcaddr) + strlen((ifn->srcaddr)),
             INFONODE_ADDR_LENGTH - strlen((ifn->srcaddr)), ".%d", sport);
    snprintf((ifn->dstaddr) + strlen((ifn->dstaddr)),
             INFONODE_ADDR_LENGTH - strlen((ifn->dstaddr)), ".%d", dport);

#if 0
    const struct ip6_hdr *ip6;
    infonode_t *ifn = (infonode_t *)infonode;

    if (IP_V(ip) == 6) {
        ip6 = (const struct ip6_hdr *)ip;
    }
    else {
        ip6 = NULL;
    }

    if (ip6) {
        if (GET_U_1(ip6->ip6_nxt) == IPPROTO_UDP)
        {
            if (sport != -1) 
            {
                snprintf((ifn->srcaddr) + strlen((ifn->srcaddr)),
                    INFONODE_ADDR_LENGTH - strlen((ifn->srcaddr)), ".%d", sport);
                snprintf((ifn->dstaddr) + strlen((ifn->dstaddr)),
                    INFONODE_ADDR_LENGTH - strlen((ifn->dstaddr)), ".%d", dport);
            }
        }
    }
    else {
        if (GET_U_1(ip->ip_p) == IPPROTO_UDP)
        {
            if (sport != -1) 
            {
                snprintf((ifn->srcaddr) + strlen((ifn->srcaddr)),
                    INFONODE_ADDR_LENGTH - strlen((ifn->srcaddr)), ".%d", sport);
                snprintf((ifn->dstaddr) + strlen((ifn->dstaddr)),
                    INFONODE_ADDR_LENGTH - strlen((ifn->dstaddr)), ".%d", dport);
            }
        }
    }
#endif
    RVoid();
}

void udp_print(ndo_t *ndo, void *infonode, const u_char *bp, 
    u_int length, const u_char *bp2, int fragmented, u_int ttl_hl)
{

    TC("Called { %s(%p, %p,%p, %u, %p, %d, %u)", __func__, ndo, infonode, 
        bp, length, bp2, fragmented, ttl_hl);

    const struct udphdr *up;
    const struct ip *ip;
    const u_char *cp;
    //const u_char *ep = ndo->ndo_snapend;
    uint16_t sport, dport;
    u_int ulen;
    const struct ip6_hdr *ip6;

    ndo->ndo_protocol = "udp";
    up = (const struct udphdr *)bp;
    ip = (const struct ip *)bp2;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;
    char icollect[256] = {0};

    if (IP_V(ip) == 6) {
        ip6 = (const struct ip6_hdr *)bp2;
    }
    else {
        ip6 = NULL;
    }

    if (!ND_TTEST_2(up->uh_dport))
    {
        udpipaddr_print(ndo, infonode, ip, -1, -1);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
        goto trunc;
    }

    sport = GET_BE_U_2(up->uh_sport);
    dport = GET_BE_U_2(up->uh_dport);

    snprintf(icollect, 256, "%hu > %hu ", sport, dport);

    if (length < sizeof(struct udphdr)) 
    {
        udpipaddr_print(ndo, infonode, ip, sport, dport);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated-udp %u (invalid)", length);
        goto trunc;
    }

    if (!ND_TTEST_2(up->uh_ulen))
    {
        udpipaddr_print(ndo, infonode, ip, sport, dport);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
        goto trunc;
    }

    ulen = GET_BE_U_2(up->uh_ulen);
    /*
     * IPv6 Jumbo Datagrams; see RFC 2675.
     * If the length is zero, and the length provided to us is
     * > 65535, use the provided length as the length.
     */
    if (ulen == 0 && length > 65535)
        ulen = length;
    if (ulen < sizeof(struct udphdr))
    {
        udpipaddr_print(ndo, infonode, ip, sport, dport);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated-udplength %u (invalid)", ulen);
        goto trunc;
    }

    ulen -= sizeof(struct udphdr);
    length -= sizeof(struct udphdr);
    if (ulen < length)
        length = ulen;

    snprintf(icollect + strlen(icollect), 256 - strlen(icollect), "Len=%hu ", length);

    cp = (const u_char *)(up + 1);
    if (cp > ndo->ndo_snapend)
    {
        udpipaddr_print(ndo, infonode, ip, sport, dport);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
        goto trunc;
    }

    su = nd_filling_l1(ifn, 0, "%s", LAYER_4_UDP_CONTENT);

    nd_filling_l2(ifn, su, 0, 2, LAYER_4_UDP_SPORT, sport);

    nd_filling_l2(ifn, su, 0, 2, LAYER_4_UDP_DPORT, dport);

    nd_filling_l2(ifn, su, 0, 2, LAYER_4_UDP_ULEN, GET_BE_U_2(up->uh_ulen));

    #if 0
    // Not supported yet
    if (ndo->ndo_packettype)
    {

    }
    #endif

    udpipaddr_print(ndo, infonode, ip, sport, dport);

    #if 0
    // Not supported yet
    if (!ndo->ndo_qflag) 
    {
        const struct sunrpc_msg *rp;
		enum sunrpc_msg_type direction;
    }
    #endif

    if (ndo->ndo_vflag && !ndo->ndo_Kflag && !fragmented)
    {
        /* Check the checksum, if possible. */
        uint16_t sum, udp_sum;
        /*
         * XXX - do this even if vflag == 1?
         * TCP does, and we do so for UDP-over-IPv6.
         */
        if (IP_V(ip) == 4 && (ndo->ndo_vflag > 1)) {
            udp_sum = GET_BE_U_2(up->uh_sum);
            if (udp_sum == 0) {
                nd_filling_l2(ifn, su, 0, 2, LAYER_4_UDP_NO_CHECKSUM, udp_sum);
            }
            else if (ND_TTEST_LEN(cp, length)) {
                sum = udp_cksum(ndo, ip, up, length + sizeof(struct udphdr));
                if (sum != 0) {
                    nd_filling_l2(ifn, su, 0, 2,
                            LAYER_4_UDP_BAD_CHECKSUM, udp_sum, in_cksum_shouldbe(udp_sum, sum));
                }
                else {
                    nd_filling_l2(ifn, su, 0, 2, LAYER_4_UDP_CHECKSUM, udp_sum);
                }
            }
        }else if (IP_V(ip) == 6) {
            /* for IPv6, UDP checksum is mandatory */
            if (ND_TTEST_LEN(cp, length))
            {
                sum = udp6_cksum(ndo, ip6, up, length + sizeof(struct udphdr));
                udp_sum = GET_BE_U_2(up->uh_sum);

                if (sum != 0) {
                    nd_filling_l2(ifn, su, 0, 2,
                            LAYER_4_UDP_BAD_CHECKSUM, udp_sum, in_cksum_shouldbe(udp_sum, sum));
                }
                else {
                    nd_filling_l2(ifn, su, 0, 2, LAYER_4_UDP_CHECKSUM, udp_sum);
                }
            }
        }
    }

    if (!ndo->ndo_qflag)
    {
        if (IS_SRC_OR_DST_PORT(NAMESERVER_PORT)) {
            /* over_tcp: FALSE, is_mdns: FALSE */
            //domain_print(ndo, cp, length, FALSE, FALSE);
        }
        else if (IS_SRC_OR_DST_PORT(BOOTPC_PORT) || IS_SRC_OR_DST_PORT(BOOTPS_PORT)) {
            // bootp_print(ndo, cp, length);
        }
        else {
            snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", (unsigned short)length);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "%s", icollect);
        }
    }

    RVoid();

trunc:

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", (unsigned short)length);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    RVoid();
}