
#include "header.h"
#include "a-f-extract.h"
#include "a-f-ethertype.h"
#include "a-f-addrtoname.h"

#include "a-f-ip.h"
#include "a-f-ipproto.h"

#if 0

0               1               2               3               4
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options and Padding                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

static const struct tok ip_option_values[] = {
    {IPOPT_EOL, "EOL"},
    {IPOPT_NOP, "NOP"},
    {IPOPT_TS, "timestamp"},
    {IPOPT_SECURITY, "security"},
    {IPOPT_RR, "RR"},
    {IPOPT_SSRR, "SSRR"},
    {IPOPT_LSRR, "LSRR"},
    {IPOPT_RA, "RA"},
    {IPOPT_RFC1393, "traceroute"},
    {0, NULL}
};

/*
 * If source-routing is present and valid, return the final destination.
 * Otherwise, return IP destination.
 *
 * This is used for UDP and TCP pseudo-header in the checksum
 * calculation.
 */
static uint32_t
ip_finddst(ndo_t *ndo, const struct ip *ip)
{
    u_int length;
    u_int len;
    const u_char *cp;

    cp = (const u_char *)(ip + 1);
    length = IP_HL(ip) * 4;
    if (length < sizeof(struct ip))
        goto trunc;
    length -= sizeof(struct ip);

    for (; length != 0; cp += len, length -= len)
    {
        int tt;

        tt = GET_U_1(cp);
        if (tt == IPOPT_EOL)
            break;
        else if (tt == IPOPT_NOP)
            len = 1;
        else
        {
            len = GET_U_1(cp + 1);
            if (len < 2)
                break;
        }
        if (length < len)
            goto trunc;
        ND_TCHECK_LEN(cp, len);
        switch (tt)
        {

        case IPOPT_SSRR:
        case IPOPT_LSRR:
            if (len < 7)
                break;
            return (GET_IPV4_TO_NETWORK_ORDER(cp + len - 4));
        }
    }
trunc:
    return (GET_IPV4_TO_NETWORK_ORDER(ip->ip_dst));
}

/*
 * Compute a V4-style checksum by building a pseudoheader.
 */
uint16_t
nextproto4_cksum(ndo_t *ndo,
                 const struct ip *ip, const uint8_t *data,
                 u_int len, u_int covlen, uint8_t next_proto)
{
    struct phdr
    {
        uint32_t src;
        uint32_t dst;
        uint8_t mbz;
        uint8_t proto;
        uint16_t len;
    } ph;
    struct cksum_vec vec[2];

    /* pseudo-header.. */
    ph.len = htons((uint16_t)len);
    ph.mbz = 0;
    ph.proto = next_proto;
    ph.src = GET_IPV4_TO_NETWORK_ORDER(ip->ip_src);
    if (IP_HL(ip) == 5)
        ph.dst = GET_IPV4_TO_NETWORK_ORDER(ip->ip_dst);
    else
        ph.dst = ip_finddst(ndo, ip);

    vec[0].ptr = (const uint8_t *)(void *)&ph;
    vec[0].len = sizeof(ph);
    vec[1].ptr = data;
    vec[1].len = covlen;
    return (in_cksum(vec, 2));
}

const char *dscp_name(uint8_t dscp)
{
    switch (dscp)
    {
        case 0x00:
            return "CS0 (Best Effort)";
        case 0x08:
            return "CS1 (Priority)";
        case 0x10:
            return "CS2";
        case 0x18:
            return "CS3";
        case 0x20:
            return "CS4";
        case 0x28:
            return "CS5";
        case 0x30:
            return "CS6 (Network Control)";
        case 0x38:
            return "CS7 (Routing Control)";
        case 0x0A:
            return "AF11";
        case 0x2E:
            return "EF (Expedited Forwarding)";
        default:
            return "Unknown";
    }
}

const char *ecn_name(uint8_t ecn)
{
    switch (ecn)
    {
        case 0:
            return "00: Non-ECN-Capable";
        case 1:
            return "01: ECN Capable Transport (ECT(1))";
        case 2:
            return "10: ECN Capable Transport (ECT(0))";
        case 3:
            return "11: Congestion Encountered (CE)";
        default:
            return "Invalid";
    }
}

#if 0

IPOPT_RA（148）
+----------+----------+--------+--------+
| Type=148 | Length=4 | Value=0x0000    |
+----------+----------+-----------------+
   1 byte     1 byte      2 bytes
Type: 0x94
Length: 4
Value: 通常为 0x0000（表示默认的 Router Alert，其他值可能为未来用途）

IPOPT_RFC1393（Traceroute，82）
+---------+--------+-----------+-----------+----------+--------+--------+--------+
| Type=82 | Length | ID Number | Outbound Hop Count   | Return Hop Count         |
+---------+--------+-----------+----------------------+--------------------------+
   1B          1B        2B               1B                     1B
Type: 0x52
Length: 8
ID Number: 2 字节唯一 ID，用于匹配响应
Outbound Hop Count: 发出的 TTL 剩余值
Return Hop Count: 回程的 TTL 剩余值（目标主机填写）


IPOPT_SECURITY（130）
+----------+-----------+----------+-------------+-----------+------------+--------------+
| Type=130 | Length=11 | Security | Compartment | Handling Restriction   | TCC          |
+----------+-----------+----------+-------------+------------------------+--------------+
   1 byte    1 byte       2 bytes      2 bytes             2 bytes         2 bytes
Type：0x82
Length：通常为 11（或更长，某些实现扩展）
Security：如 0x0000 表示 UNCLASSIFIED，0xf135 表示 SECRET（不同系统可能不同编码）
Compartment：2 字节的 compartment 编号
Handling Restriction：处理限制字段，表示特定安全规则
Transmission Control Code (TCC)：2 字节，传输控制码（可选）


IPOPT_TS(用于记录经过时间，可能还附带 IP 地址)
类型 = 0（只记录时间戳）
+--------+--------+---------+--------+--------+--------+ ...
| Type=68| Length | Pointer | OFLW+FL| TS1(4B)| TS2(4B)| ...
+--------+--------+---------+--------+--------+--------+
   1B       1B        1B        1B       4B       4B

类型 = 1（记录IP+时间）
+--------+--------+---------+--------+--------+--------+--------+ ...
| Type=68| Length | Pointer | OFLW+FL| IP1    | TS1    | IP2    | ...
+--------+--------+---------+--------+--------+--------+--------+



IPOPT_RR(记录路由器地址，每个路由器在转发时将自己的地址写入)
+--------+--------+---------+--------+--------+--------+ ...
| Type=7 | Length | Pointer |  Addr1 |  Addr2 |  Addr3 | ...
+--------+--------+---------+--------+--------+--------+
   1B       1B        1B        4B       4B       4B


IPOPT_SSRR（Strict Source Route）(发送端提供严格路径，每跳必须按指定顺序)
+---------+--------+---------+--------+--------+--------+ ...
| Type=137| Length | Pointer | IP1    | IP2    | IP3    | ...
+---------+--------+---------+--------+--------+--------+
   1B        1B        1B        4B       4B       4B


IPOPT_LSRR（Loose Source Route）(与 SSRR 类似，但可以“绕路”，中间允许非指定路由器转发)
+---------+--------+---------+--------+--------+--------+ ...
| Type=131| Length | Pointer | IP1    | IP2    | IP3    | ...
+---------+--------+---------+--------+--------+--------+

#endif

char * ipopt_ts_flag (u_int flag)
{

    if (flag == IPOPT_TS_TSONLY)
        return "TSONLY";

    if (flag == IPOPT_TS_TSANDADDR)
        return "TS+ADDR";

    if (flag == IPOPT_TS_PRESPEC)
        return "PRESPEC";

    return "bad ts type";
}


/*
 * print IP options.
   If truncated return -1, else 0.
 */
static int
ip_optprint(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, const u_char *cp, u_int length)
{

    u_int option_len = 0;

    u_int hoplen, ptr, oflw, flag, len;

    for (; length > 0; cp += option_len, length -= option_len) 
    {
        u_int option_code = 0;

        option_code = GET_U_1(cp);
        nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_TYPE,
            tok2str(ip_option_values, "unknown", option_code), option_code);

        if (option_code == IPOPT_EOL || option_code == IPOPT_NOP) {
            option_len = 1;
        }
        else {
            option_len = GET_U_1(cp + 1);
            if (option_len < 2) {
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH_ERR, 
                    option_len, option_len, "<", 2);
                return 0;
            }
        }

        if (option_len > length) {
            nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH_ERR, 
                option_len, option_len, ">", length);
            return 0;
        }

        if (!ND_TTEST_LEN(cp, option_len))
            goto trunc;
        
        switch (option_code)
        {
            case IPOPT_EOL:
                return 0;

            case IPOPT_TS:
                if (option_len < 4) {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH_ERR, 
                        option_len, option_len, "<", 4);
                    ifn->idx += (option_len - 2);
                    break;
                }

                hoplen = ((GET_U_1(cp + 3) & 0xF) != IPOPT_TS_TSONLY) ? 8 : 4;
                if ((option_len - 4) & (hoplen - 1)) {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH_ERR1, 
                        option_len, option_len, "%%", hoplen);
                }
                else {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH, option_len);
                }

                ptr = GET_U_1(cp + 2) - 1;
                if (ptr < 4 || ((ptr - 4) & (hoplen - 1)) || ptr > option_len + 1) {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_POINTER_ERR, ptr + 1);
                }
                else {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_POINTER, ptr + 1);
                }

                oflw = GET_U_1(cp + 3) & 0xF;
                flag = GET_U_1(cp + 3) >> 4;
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_OFLWFL, flag, oflw, ipopt_ts_flag(oflw));

                if (oflw != IPOPT_TS_TSONLY && oflw != IPOPT_TS_TSANDADDR && oflw != IPOPT_TS_PRESPEC) {
                    ifn->idx += (option_len - 4);
                    break;
                }

                for (len = 4; len < option_len; len += hoplen) 
                {
                    if (!ND_TTEST_LEN(cp + len, hoplen))
                        goto trunc;
                    
                    if (hoplen == 8) {
                        nd_filling_l2(ifn, su, 0, 4, LAYER_3_IP_OPTION_ADDR, GET_IPADDR_STRING(cp + len));
                    }

                    nd_filling_l2(ifn, su, 0, 4, LAYER_3_IP_OPTION_TS, GET_BE_U_4(cp + len + hoplen - 4));
                }

                break;
            case IPOPT_RR:
            case IPOPT_SSRR:
            case IPOPT_LSRR:
                if (option_len < 3) {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH_ERR, option_len, option_len, "<", 3);
                    ifn->idx += (option_len - 2);
                    break;
                }

                if ((option_len + 1) & 3) {
                    nd_filling_l2(ifn, su, 0, 1, 
                        LAYER_3_IP_OPTION_LENGTH_ERR1, option_len, option_len + 1, "%%", 4);
                }
                else {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH, option_len);
                }

                ptr = GET_U_1(cp + 2) - 1;
                if (ptr < 3 || ((ptr + 1) & 3) || ptr > length + 1) {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_POINTER_ERR, ptr + 1);
                }
                else {
                    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_POINTER, ptr + 1);
                }

                for (len = 3; len < option_len; len += 4) {
                    if (!ND_TTEST_LEN(cp + len, 4))
                        goto trunc;

                    nd_filling_l2(ifn, su, 0, 4, LAYER_3_IP_OPTION_ADDR, GET_IPADDR_STRING(cp + len));
                }

                break;

            case IPOPT_RA:
                if (option_len < 4) {
                    nd_filling_l2(ifn, su, 0, 1, 
                        LAYER_3_IP_OPTION_LENGTH_ERR, option_len, option_len, "<", 4);
                    ifn->idx += (option_len - 2);
                    break;
                }

                if (!ND_TTEST_LEN(cp + 3, 1))
                    goto trunc;

                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH, option_len);
                nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_OPTION_VALUE_04HEX, GET_BE_U_2(cp + 2));
                break;

            case IPOPT_SECURITY:
                nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_OPTION_LENGTH, option_len);
                ifn->idx += (option_len - 2);
                break;

            case IPOPT_NOP:
            default:
                break;
        }
    }

    return 0;

trunc:
    return -1;
}

#define IP_RES 0x8000

static const struct tok ip_frag_values[] = {
    {IP_MF, "+"},
    {IP_DF, "DF"},
    {IP_RES, "rsvd"}, /* The RFC3514 evil ;-) bit */
    {0, NULL}
};

/*
 * print an IP datagram.
 */
void ip_print(ndo_t *ndo, void *infonode, const u_char *bp, const u_int length)
{

    TC("Called { %s(%p, %p, %p, %u)", __func__, ndo, infonode, bp, length);

    const struct ip *ip;

    u_int hlen;
    u_int len;
    u_int off;
    struct cksum_vec vec[1];
    uint8_t ip_tos, ip_ttl, ip_proto;
    uint16_t sum, ip_sum;
    const char * p_name = NULL;
    int presumed_tso = 0;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    ndo->ndo_protocol = "ip";
    ip = (const struct ip *)bp;

    if (length < (sizeof(struct ip)))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "length %u < %lu (invalid)",
                 length, (sizeof(struct ip)));
        goto invalid;
    }

    if (IP_V(ip) != 4) 
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "version %u != %u (invalid)",
                 IP_V(ip), 4);
        goto invalid;
    }

    hlen = IP_HL(ip) * 4;
    if (hlen < (sizeof(struct ip)))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "header length %u < %lu (invalid)",
                 hlen, (sizeof(struct ip)));
        goto invalid;
    }

    len = GET_BE_U_2(ip->ip_len);
    if (len > length) 
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "total length %u > length %u (invalid)",
                 len, length);
    }

    if (len == 0) 
    {
        /* we guess that it is a TSO send */
        len = length;
        presumed_tso = 1;
    }
    else 
    {
        if (len < hlen) 
        {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "total length %u < %u (invalid)",
                    len, hlen);
            goto invalid;
        }
    }

    if (!ND_TTEST_LEN(ip, sizeof(*ip)))
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

    su = nd_filling_l1(ifn, 0, LAYER_3_IP_FORMAT, LAYER_3_IP_CONTENT);

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_VERSION, IP_V(ip));
    ifn->idx -= 1;
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_HDRLEN, hlen);

    ip_tos = GET_U_1(ip->ip_tos);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_TOS, 
        ip_tos, dscp_name(ip_tos >> 2), ecn_name(ip_tos & 0x03));

    if (presumed_tso) {
        nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_TOTAL_LENGTH_TSO, length);
    }
    else {
        nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_TOTAL_LENGTH, len);
    }

    nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_IDENTIFICATION, GET_BE_U_2(ip->ip_id));

    off = GET_BE_U_2(ip->ip_off);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_FLAGS, 
        ((off & (IP_RES | IP_DF | IP_MF)) >> 13), 
        bittok2str(ip_frag_values, "none", off & (IP_RES|IP_DF|IP_MF))
    );
    ifn->idx -= 2;
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_FRAGMENT_OFFSET, (off & IP_OFFMASK) * 8);

    ip_ttl = GET_U_1(ip->ip_ttl);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_TIME_TO_LIVE, ip_ttl);

    ip_proto = GET_U_1(ip->ip_p);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_IP_PROTOCOL, ip_proto, 
        tok2str(ipproto_values, "unknown", ip_proto));

    vec[0].ptr = (const uint8_t *)(const void *)ip;
    vec[0].len = hlen;
    sum = in_cksum(vec, 1);
    ip_sum = GET_BE_U_2(ip->ip_sum);
    if (sum != 0) {
        nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_BAD_HEADER_CHECKSUM,
            ip_sum, in_cksum_shouldbe(ip_sum, sum));
    }
    else {
        nd_filling_l2(ifn, su, 0, 2, LAYER_3_IP_HEADER_CHECKSUM, ip_sum);
    }

    nd_filling_l2(ifn, su, 0, 4, LAYER_3_IP_SOURCE_ADDRESS, GET_IPADDR_STRING(ip->ip_src));
    nd_filling_l2(ifn, su, 0, 4, LAYER_3_IP_DESTINATION_ADDRESS, GET_IPADDR_STRING(ip->ip_dst));

    snprintf(ifn->srcaddr, INFONODE_ADDR_LENGTH, "%s", GET_IPADDR_STRING(ip->ip_src));
    snprintf(ifn->dstaddr, INFONODE_ADDR_LENGTH, "%s", GET_IPADDR_STRING(ip->ip_dst));

    len -= hlen;

    int bak_idx = ifn->idx;

    if ((hlen - sizeof(struct ip)) > 0) 
    {
        if (ip_optprint(ndo, ifn, su, (const u_char *)(ip + 1), hlen - sizeof(struct ip)) == -1) 
        {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "truncated option (invalid)");
            nd_pop_packet_info(ndo);
            goto invalid;
        }
    }

    if ((off & IP_OFFMASK) == 0) {
        uint8_t nh = GET_U_1(ip->ip_p);
        if (!ND_TTEST_LEN((const u_char *)ip, hlen)) {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, 
                "remaining caplen(%u) < header length(%u) (invalid)", 
                ND_BYTES_AVAILABLE_AFTER((const u_char *)ip), hlen
            );
            nd_trunc_longjmp(ndo);
        }
        //index = index + hlen - sizeof(struct ip);
        ifn->idx = bak_idx + hlen - sizeof(struct ip);
        ip_demux_print(ndo, infonode, (const u_char *)ip + hlen, len, 4,
                       off & IP_MF, GET_U_1(ip->ip_ttl), nh, bp);
    }
    else 
    {
        p_name = netdb_protoname(ip_proto);
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        if (p_name) 
        {
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", p_name);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                     "fragmented ip protocol (proto=%s %u, off=%u)",
                     p_name, ip_proto, off
                );
        }
        else
        {
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%u", ip_proto);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH,
                     "fragmented ip protocol (proto=%u, off=%u)",
                     ip_proto, off
                );
        }
        
    }

    nd_pop_packet_info(ndo);
    RVoid();

invalid:

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    RVoid();
 }
