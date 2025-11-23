
#include "header.h"
#include "a-f-extract.h"
#include "a-f-ethertype.h"
#include "a-f-addrtoname.h"

#include "a-f-ip6.h"
#include "a-f-ipproto.h"

#if 0
0               1               2               3               4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Source Address (128 bits)                 |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                 Destination Address (128 bits)                |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Version	                4 bits	    协议版本号, IPv6为6
Traffic Class	        8 bits	    类似IPv4的TOS, 用于QoS或优先级
Flow Label	            20 bits	    用于标识同一流的IP包（如VoIP）
Payload Length	        16 bits	    除去IPv6头部之外的负载长度
Next Header	            8 bits	    指示下一个协议头（如TCP/UDP/扩展头）
Hop Limit	            8 bits	    类似IPv4的TTL, 每跳减一
Source Address	        128 bits	源 IPv6 地址
Destination Address	    128 bits	目标 IPv6 地址

#endif

/*
 * If routing headers are presend and valid, set dst to the final destination.
 * Otherwise, set it to the IPv6 destination.
 *
 * This is used for UDP and TCP pseudo-header in the checksum
 * calculation.
 */
static void
ip6_finddst(ndo_t *ndo, nd_ipv6 *dst,
            const struct ip6_hdr *ip6)
{
    const u_char *cp;
    u_int advance;
    u_int nh;
    const void *dst_addr;
    const struct ip6_rthdr *dp;
    const struct ip6_rthdr0 *dp0;
    const struct ip6_srh *srh;
    const u_char *p;
    int i, len;

    cp = (const u_char *)ip6;
    advance = sizeof(struct ip6_hdr);
    nh = GET_U_1(ip6->ip6_nxt);
    dst_addr = (const void *)ip6->ip6_dst;

    while (cp < ndo->ndo_snapend)
    {
        cp += advance;

        switch (nh)
        {

        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MOBILITY_OLD:
        case IPPROTO_MOBILITY:
            /*
             * These have a header length byte, following
             * the next header byte, giving the length of
             * the header, in units of 8 octets, excluding
             * the first 8 octets.
             */
            advance = (GET_U_1(cp + 1) + 1) << 3;
            nh = GET_U_1(cp);
            break;

        case IPPROTO_FRAGMENT:
            /*
             * The byte following the next header byte is
             * marked as reserved, and the header is always
             * the same size.
             */
            advance = sizeof(struct ip6_frag);
            nh = GET_U_1(cp);
            break;

        case IPPROTO_ROUTING:
            /*
             * OK, we found it.
             */
            dp = (const struct ip6_rthdr *)cp;
            ND_TCHECK_SIZE(dp);
            len = GET_U_1(dp->ip6r_len);
            switch (GET_U_1(dp->ip6r_type))
            {

            case IPV6_RTHDR_TYPE_0:
            case IPV6_RTHDR_TYPE_2: /* Mobile IPv6 ID-20 */
                dp0 = (const struct ip6_rthdr0 *)dp;
                if (len % 2 == 1)
                    goto trunc;
                len >>= 1;
                p = (const u_char *)dp0->ip6r0_addr;
                for (i = 0; i < len; i++)
                {
                    ND_TCHECK_16(p);
                    dst_addr = (const void *)p;
                    p += 16;
                }
                break;
            case IPV6_RTHDR_TYPE_4:
                /* IPv6 Segment Routing Header (SRH) */
                srh = (const struct ip6_srh *)dp;
                if (len % 2 == 1)
                    goto trunc;
                p = (const u_char *)srh->srh_segments;
                /*
                 * The list of segments are encoded in the reverse order.
                 * Accordingly, the final DA is encoded in srh_segments[0]
                 */
                ND_TCHECK_16(p);
                dst_addr = (const void *)p;
                break;

            default:
                break;
            }

            /*
             * Only one routing header to a customer.
             */
            goto done;

        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_IPCOMP:
        default:
            /*
             * AH and ESP are, in the RFCs that describe them,
             * described as being "viewed as an end-to-end
             * payload" "in the IPv6 context, so that they
             * "should appear after hop-by-hop, routing, and
             * fragmentation extension headers".  We assume
             * that's the case, and stop as soon as we see
             * one.  (We can't handle an ESP header in
             * the general case anyway, as its length depends
             * on the encryption algorithm.)
             *
             * IPComp is also "viewed as an end-to-end
             * payload" "in the IPv6 context".
             *
             * All other protocols are assumed to be the final
             * protocol.
             */
            goto done;
        }
    }

done:
trunc:
    GET_CPY_BYTES(dst, dst_addr, sizeof(nd_ipv6));
}

/*
 * Compute a V6-style checksum by building a pseudoheader.
 */
uint16_t
nextproto6_cksum(ndo_t *ndo,
                 const struct ip6_hdr *ip6, const uint8_t *data,
                 u_int len, u_int covlen, uint8_t next_proto)
{
    struct
    {
        nd_ipv6 ph_src;
        nd_ipv6 ph_dst;
        uint32_t ph_len;
        uint8_t ph_zero[3];
        uint8_t ph_nxt;
    } ph;
    struct cksum_vec vec[2];
    u_int nh;

    /* pseudo-header */
    memset(&ph, 0, sizeof(ph));
    GET_CPY_BYTES(&ph.ph_src, ip6->ip6_src, sizeof(nd_ipv6));
    nh = GET_U_1(ip6->ip6_nxt);
    switch (nh)
    {

    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
    case IPPROTO_MOBILITY_OLD:
    case IPPROTO_MOBILITY:
    case IPPROTO_FRAGMENT:
    case IPPROTO_ROUTING:
        /*
         * The next header is either a routing header or a header
         * after which there might be a routing header, so scan
         * for a routing header.
         */
        ip6_finddst(ndo, &ph.ph_dst, ip6);
        break;

    default:
        GET_CPY_BYTES(&ph.ph_dst, ip6->ip6_dst, sizeof(nd_ipv6));
        break;
    }
    ph.ph_len = htonl(len);
    ph.ph_nxt = next_proto;

    vec[0].ptr = (const uint8_t *)(void *)&ph;
    vec[0].len = sizeof(ph);
    vec[1].ptr = data;
    vec[1].len = covlen;

    return in_cksum(vec, 2);
}

/*
 * print an IP6 datagram.
 */
void ip6_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length)
{

    TC("Called { %s(%p, %p, %p, %u)", __func__, ndo, infonode, bp, length);

    const struct ip6_hdr *ip6;
    int advance;
    u_int len;
    u_int total_advance;
    const u_char *cp;
    uint32_t payload_len;
    uint8_t ph, nh;
    int fragmented = 0;
    u_int flow;

    int found_extension_header;
    int found_jumbo;
    int found_hbh;

    ndo->ndo_protocol = "ip6";
    ip6 = (const struct ip6_hdr *)bp;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    if (length < sizeof(struct ip6_hdr))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "length %u < %lu (invalid)",
                 length, (sizeof(struct ip6_hdr)));
        goto invalid;
    }

    if (IP6_VERSION(ip6) != 6)
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "version %u != %u (invalid)",
                 IP6_VERSION(ip6), 6);
        goto invalid;
    }

    payload_len = GET_BE_U_2(ip6->ip6_plen);

    /*
     * RFC 1883 says:
     *
     * The Payload Length field in the IPv6 header must be set to zero
     * in every packet that carries the Jumbo Payload option.  If a
     * packet is received with a valid Jumbo Payload option present and
     * a non-zero IPv6 Payload Length field, an ICMP Parameter Problem
     * message, Code 0, should be sent to the packet's source, pointing
     * to the Option Type field of the Jumbo Payload option.
     *
     * Later versions of the IPv6 spec don't discuss the Jumbo Payload
     * option.
     *
     * If the payload length is 0, we temporarily just set the total
     * length to the remaining data in the packet (which, for Ethernet,
     * could include frame padding, but if it's a Jumbo Payload frame,
     * it shouldn't even be sendable over Ethernet, so we don't worry
     * about that), so we can process the extension headers in order
     * to *find* a Jumbo Payload hop-by-hop option and, when we've
     * processed all the extension headers, check whether we found
     * a Jumbo Payload option, and fail if we haven't.
     */

    if (payload_len != 0)
    {
        len = payload_len + sizeof(struct ip6_hdr);
        if (len > length) 
        {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, 
                "header+payload length %u > length %u (invalid)", len, length);
            goto invalid;
        }
    }
    else 
    {
        len = length + sizeof(struct ip6_hdr);
    }

    if (!ND_TTEST_LEN(ip6, sizeof(*ip6)))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
        goto invalid;
    }

    /*
     * Cut off the snapshot length to the end of the IP payload.
     */
    if (!nd_push_snaplen(ndo, bp, len))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "can't push snaplen on buffer stack (invalid)");
        goto invalid;
    }

    su = nd_filling_l1(ifn, 0, LAYER_3_IP6_FORMAT, LAYER_3_IP6_CONTENT);

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_VERSION, IP6_VERSION(ip6));
    ifn->idx -= 1;

    flow = GET_BE_U_4(ip6->ip6_flow);
    nd_filling_l2(ifn, su, 0, 4, 
        LAYER_3_IP6_TC_FL, (flow & 0x0ff00000) >> 20, flow & 0x000fffff);

    nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP6_PAYLOAD_LEN, payload_len);

    ph = 255;
    nh = GET_U_1(ip6->ip6_nxt);
    nd_filling_l2(ifn, su, 0, 1, 
        LAYER_3_IP6_NEXT_HEADER, nh, tok2str(ipproto_values,"unknown",nh));

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP6_HOP_LIMIT, GET_U_1(ip6->ip6_hlim));
    
    nd_filling_l2(ifn, su, 0, 16, LAYER_3_IP6_SOURCE_ADDRESS, GET_IP6ADDR_STRING(ip6->ip6_src));

    nd_filling_l2(ifn, su, 0, 16, LAYER_3_IP6_DESTINATION_ADDRESS, GET_IP6ADDR_STRING(ip6->ip6_dst));

    snprintf(ifn->srcaddr, INFONODE_ADDR_LENGTH, "%s", GET_IP6ADDR_STRING(ip6->ip6_src));
    snprintf(ifn->dstaddr, INFONODE_ADDR_LENGTH, "%s", GET_IP6ADDR_STRING(ip6->ip6_dst));

    cp = (const u_char *)ip6;
    advance = sizeof(struct ip6_hdr);
    total_advance = 0;
    /* Process extension headers */
    found_extension_header = 0;
    found_jumbo = 0;
    found_hbh = 0;

    while (cp < ndo->ndo_snapend && advance > 0) 
    {
        if (len < advance)
        {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "truncated (invalid)");
            goto invalid;
        }

        cp += advance;
        len -= advance;
        total_advance += advance;

        switch (nh) 
        {
            case IPPROTO_HOPOPTS:
                /*
                 * The Hop-by-Hop Options header, when present,
                 * must immediately follow the IPv6 header (RFC 8200)
                 */
                if (found_hbh == 1)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, 
                        "The Hop-by-Hop Options header was already found (invalid)");
                    goto invalid;
                }
                if (ph != 255)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                        "The Hop-by-Hop Options header don't follow the IPv6 header (invalid)");
                    goto invalid;
                }
                advance = hbhopt_process(ndo, infonode, su, cp, &found_jumbo, &payload_len);
                if (payload_len == 0 && found_jumbo == 0)
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "No valid Jumbo Payload Hop-by-Hop option found (invalid)");
                    goto invalid;
                }
                if (advance < 0) 
                {
                    nd_pop_packet_info(ndo);
                    goto invalid;
                }
                found_extension_header = 1;
                found_hbh = 1;
                nh = GET_U_1(cp);
                break;
            case IPPROTO_DSTOPTS:
                advance = dstopt_process(ndo, infonode, su, cp);
                if (advance < 0)
                {
                    nd_pop_packet_info(ndo);
                    goto invalid;
                }
                found_extension_header = 1;
                nh = GET_U_1(cp);
                break;
            case IPPROTO_FRAGMENT:
                advance = frag6_print(ndo, infonode, su, cp, (const char *)ip6);
                // 将 下面的判断拆成两个
                if (advance < 0 || ndo->ndo_snapend <= cp + advance) 
                {
                    nd_pop_packet_info(ndo);
                    goto invalid;
                }
                found_extension_header = 1;
                nh = GET_U_1(cp);
                fragmented = 1;
                break;
            case IPPROTO_MOBILITY_OLD:
            case IPPROTO_MOBILITY:
                /*
                 * RFC 3775 says that
                 * the next header field in a mobility header
                 * should be IPPROTO_NONE, but speaks of
                 * the possibility of a future extension in
                 * which payload can be piggybacked atop a
                 * mobility header.
                 */
                advance = mobility_print(ndo, infonode, su, cp, (const char *)ip6);
                if (advance < 0)
                {
                    nd_pop_packet_info(ndo);
                    RVoid();
                }
                found_extension_header = 1;
                nh = GET_U_1(cp);
                nd_pop_packet_info(ndo);
                RVoid();
                break;
            case IPPROTO_ROUTING:
                if (!ND_TTEST_LEN(cp, 1))
                {
                    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                             "Routing Header Truncate (invalid)");
                    goto invalid;
                }
                advance = rt6_print(ndo, infonode, su, cp, (const char *)ip6);
                if (advance < 0)
                {
                    nd_pop_packet_info(ndo);
                    RVoid();
                }
                found_extension_header = 1;
                nh = GET_U_1(cp);
                break;
            default:
                /*
                 * Not an extension header; hand off to the
                 * IP protocol demuxer.
                 */
                if (found_jumbo)
                {
                    /*
                     * We saw a Jumbo Payload option.
                     * Set the length to the payload length
                     * plus the IPv6 header length, and
                     * change the snapshot length accordingly.
                     *
                     * But make sure it's not shorter than
                     * the total number of bytes we've
                     * processed so far.
                     */
                    len = payload_len + sizeof(struct ip6_hdr);
                    if (len < total_advance)
                    {
                        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Truncate (invalid)");
                        goto invalid;
                    }
                    if (len > length)
                    {
                        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "(invalid)");
                        goto invalid;
                    }
                    nd_change_snaplen(ndo, bp, len);

                    /*
                     * Now subtract the length of the IPv6
                     * header plus extension headers to get
                     * the payload length.
                     */
                    len -= total_advance;
                }
                else 
                {
                    /*
                     * We didn't see a Jumbo Payload option;
                     * was the payload length zero?
                     */
                    if (payload_len == 0)
                    {
                        /*
                         * Yes.  If we found an extension
                         * header, treat that as a truncated
                         * packet header, as there was
                         * no payload to contain an
                         * extension header.
                         */
                        if (found_extension_header) 
                        {
                            goto invalid;
                            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "(invalid)");
                        }
                        /*
                         * OK, we didn't see any extension
                         * header, but that means we have
                         * no payload, so set the length
                         * to the IPv6 header length,
                         * and change the snapshot length
                         * accordingly.
                         */
                        len = sizeof(struct ip6_hdr);
                        nd_change_snaplen(ndo, bp, len);

                        /*
                         * Now subtract the length of
                         * the IPv6 header plus extension
                         * headers (there weren't any, so
                         * that's just the IPv6 header
                         * length) to get the payload length.
                         */
                        len -= total_advance;
                    }
                }
                ip_demux_print(ndo, infonode, cp, len, 6, fragmented,
                               GET_U_1(ip6->ip6_hlim), nh, bp);
                nd_pop_packet_info(ndo);
                RVoid();
        }
        ph = nh;
        /* ndo_protocol reassignment after xxx_print() calls */
        ndo->ndo_protocol = "ip6";
    }

    nd_pop_packet_info(ndo);
    RVoid();

invalid:

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    RVoid();
}
