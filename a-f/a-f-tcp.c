
#include "ndo.h"
#include "header.h"
#include "a-f-ip.h"
#include "a-f-ip6.h"
#include "a-f-tcp.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"

#define LAYER_4_TCP_CONTENT             "Transmission Control Protocol: "
#define LAYER_4_TCP_SPORT               "source port: %hu"
#define LAYER_4_TCP_DPORT               "destination port: %hu"
#define LAYER_4_TCP_SEQ                 "sequence number: %u"
#define LAYER_4_TCP_ACK                 "acknowledgement number: %u"
#define LAYER_4_TCP_OFFX2               "header length: %u(%u), resv: %u"
#define LAYER_4_TCP_FLAGS               "flags: %s(%u)"
#define LAYER_4_TCP_WIN                 "window size: %hu"
#define LAYER_4_TCP_CHECKSUM            "check sum: 0x%04x"
#define LAYER_4_TCP_URP                 "urgent pointer: %hu"
#define LAYER_4_TCP_OPTION_TYPE         "option type: %s (%u)"
#define LAYER_4_TCP_OPTION_LEN          "length: %u"


#define MAX_RST_DATA_LEN 30

struct tha
{
    nd_ipv4 src;
    nd_ipv4 dst;
    u_int port;
};

struct tcp_seq_hash
{
    struct tcp_seq_hash *nxt;
    struct tha addr;
    uint32_t seq;
    uint32_t ack;
};

struct tha6
{
    nd_ipv6 src;
    nd_ipv6 dst;
    u_int port;
};

struct tcp_seq_hash6
{
    struct tcp_seq_hash6 *nxt;
    struct tha6 addr;
    uint32_t seq;
    uint32_t ack;
};

#define TSEQ_HASHSIZE 919

/* These tcp options do not have the size octet */
#define ZEROLENOPT(o) ((o) == TCPOPT_EOL || (o) == TCPOPT_NOP)

//static struct tcp_seq_hash tcp_seq_hash4[TSEQ_HASHSIZE];
//static struct tcp_seq_hash6 tcp_seq_hash6[TSEQ_HASHSIZE];

static const struct tok tcp_flag_values[] = {
    {TH_FIN, "FIN"},
    {TH_SYN, "SYN"},
    {TH_RST, "RST"},
    {TH_PUSH, "PUSH"},
    {TH_ACK, "ACK"},
    {TH_URG, "URG"},
    {TH_ECNECHO, "ECN-Echo"},
    {TH_CWR, "CWR"},
    {0, NULL}
};

#if 0
static const struct tok tcp_option_values[] = {
    {TCPOPT_EOL, "eol"},
    {TCPOPT_NOP, "nop"},
    {TCPOPT_MAXSEG, "mss"},
    {TCPOPT_WSCALE, "wscale"},
    {TCPOPT_SACKOK, "sackOK"},
    {TCPOPT_SACK, "sack"},
    {TCPOPT_ECHO, "echo"},
    {TCPOPT_ECHOREPLY, "echoreply"},
    {TCPOPT_TIMESTAMP, "TS"},
    {TCPOPT_CC, "cc"},
    {TCPOPT_CCNEW, "ccnew"},
    {TCPOPT_CCECHO, "ccecho"},
    {TCPOPT_SIGNATURE, "md5"},
    {TCPOPT_SCPS, "scps"},
    {TCPOPT_UTO, "uto"},
    {TCPOPT_TCPAO, "tcp-ao"},
    {TCPOPT_MPTCP, "mptcp"},
    {TCPOPT_FASTOPEN, "tfo"},
    {TCPOPT_EXPERIMENT2, "exp"},
    {0, NULL}
};
#endif

static const struct tok tcp_option_long_values[] = {
    {TCPOPT_EOL, "end of option list (EOL)"},
    {TCPOPT_NOP, "no-operation (NOP)"},
    {TCPOPT_MAXSEG, "maximum segment size (MSS)"},
    {TCPOPT_WSCALE, "window scale (WS)"},
    {TCPOPT_SACKOK, "sack permitted"},
    {TCPOPT_SACK, "sack (selective acknowledgment)"},
    {TCPOPT_ECHO, "echo (obsolete)"},
    {TCPOPT_ECHOREPLY, "echo reply (obsolete)"},
    {TCPOPT_TIMESTAMP, "timestamps (TS)"},
    {TCPOPT_CC, "cc (obsolete)"},
    {TCPOPT_CCNEW, "cc.new (obsolete)"},
    {TCPOPT_CCECHO, "cc.echo (obsolete)"},
    {TCPOPT_SIGNATURE, "md5 signature (RFC 2385)"},
    {TCPOPT_SCPS, "scps capabilities"},
    {TCPOPT_UTO, "user timeout option"},
    {TCPOPT_TCPAO, "tcp authentication option"},
    {TCPOPT_MPTCP, "multipath tcp (MPTCP)"},
    {TCPOPT_FASTOPEN, "tcp fast open cookie"},
    {TCPOPT_EXPERIMENT2, "experimental option"},
    {0, NULL}
};

/*
 * RFC1122 says the following on data in RST segments:
 *
 *         4.2.2.12  RST Segment: RFC-793 Section 3.4
 *
 *            A TCP SHOULD allow a received RST segment to include data.
 *
 *            DISCUSSION
 *                 It has been suggested that a RST segment could contain
 *                 ASCII text that encoded and explained the cause of the
 *                 RST.  No standard has yet been established for such
 *                 data.
 *
 */

static void
print_tcp_rst_data(ndo_t *ndo, const u_char *sp, u_int length, char * buffer)
{
    u_char c;

    if (ND_TTEST_LEN(sp, length))
    {
        sprintf(buffer, "%s", " RST");
    }
    else
    {
        sprintf(buffer, "%s", " !RST");
    }

    if (length > MAX_RST_DATA_LEN)
    {
        length = MAX_RST_DATA_LEN; /* can use -X for longer */
        //ND_PRINT("+");             /* indicate we truncate */
        sprintf(buffer + strlen(buffer), "%s", "+");
    }
    sprintf(buffer + strlen(buffer), "%s", " ");
    while (length && sp < ndo->ndo_snapend)
    {
        c = GET_U_1(sp);
        sp++;
        fn_print_char(ndo, c, buffer + strlen(buffer));
        length--;
    }
}

static uint16_t
tcp_cksum(ndo_t *ndo, const struct ip *ip, const struct tcphdr *tp, u_int len)
{
    return nextproto4_cksum(ndo, ip, (const uint8_t *)tp, len, len,
                            IPPROTO_TCP);
}

static uint16_t
tcp6_cksum(ndo_t *ndo, const struct ip6_hdr *ip6, const struct tcphdr *tp, u_int len)
{
    return nextproto6_cksum(ndo, ip6, (const uint8_t *)tp, len, len,
                            IPPROTO_TCP);
}

void tcp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length,
               const u_char *bp2, int fragmented)
{
    TC("Called { %s(%p, %p, %p, %u, %p, %d)", __func__, 
        ndo, infonode, bp, length, bp2, fragmented);

    const struct tcphdr *tp;
    const struct ip *ip;
    u_char flags;
    u_int hlen;
    //char ch;
    uint16_t sport, dport, win, urp;
    uint32_t seq, ack/*, thseq, thack*/;
    u_int utoval;
    //uint16_t magic;
    //int rev;
    const struct ip6_hdr *ip6;
    u_int header_len; /* Header length in bytes */
    char icollect[256] = {0};

    ndo->ndo_protocol = "tcp";
    tp = (const struct tcphdr *)bp;
    ip = (const struct ip *)bp2;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    if (IP_V(ip) == 6) {
        ip6 = (const struct ip6_hdr *)bp2;
    }
    else {
        ip6 = NULL;
    }

    //ch = '\0';

    if (!ND_TTEST_2(tp->th_dport)) {
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        RVoid();
    }

    sport = GET_BE_U_2(tp->th_sport);
    dport = GET_BE_U_2(tp->th_dport);
    snprintf(icollect, 256, "%hu > %hu ", sport, dport);

    snprintf((ifn->srcaddr) + strlen((ifn->srcaddr)),
             INFONODE_ADDR_LENGTH - strlen((ifn->srcaddr)), ".%d", sport);
    snprintf((ifn->dstaddr) + strlen((ifn->dstaddr)),
             INFONODE_ADDR_LENGTH - strlen((ifn->dstaddr)), ".%d", dport);

    if (!ND_TTEST_LEN(tp, sizeof(*(tp)))) {
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        RVoid();
    }

    hlen = TH_OFF(tp) * 4;

    if (hlen < sizeof(*tp)) {
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "head length too short (%u < %lu)",
                hlen, sizeof(*tp));
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        RVoid();
    }

    seq = GET_BE_U_4(tp->th_seq);
    ack = GET_BE_U_4(tp->th_ack);
    win = GET_BE_U_2(tp->th_win);
    urp = GET_BE_U_2(tp->th_urp);

    if (hlen > length) {
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "head length too long (%u > %u)",
                hlen, length);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        RVoid();
    }

    su = nd_filling_l1(ifn, 0, "%s", LAYER_4_TCP_CONTENT);
    nd_filling_l2(ifn, su, 0, 2, LAYER_4_TCP_SPORT, sport);
    nd_filling_l2(ifn, su, 0, 2, LAYER_4_TCP_DPORT, dport);

    flags = GET_U_1(tp->th_flags);
    if (ndo->ndo_vflag > 1 || length > 0 || flags & (TH_SYN | TH_FIN | TH_RST)) {
        if ((length - hlen) == 0) {
            nd_filling_l2(ifn, su, 0, 4, LAYER_4_TCP_SEQ, seq);
        }
        else if ((length - hlen) > 0) {
            nd_filling_l2(ifn, su, 0, 4, LAYER_4_TCP_SEQ ":(length %u)", seq, seq + length - hlen);
        }
    }

    snprintf(icollect + strlen(icollect), 256 - strlen(icollect), "[%s] ", bittok2str(tcp_flag_values, "none", flags));
    snprintf(icollect + strlen(icollect), 256 - strlen(icollect), "seq=%u ", seq);

    nd_filling_l2(ifn, su, 0, 4, LAYER_4_TCP_ACK, ack);

    snprintf(icollect + strlen(icollect), 256 - strlen(icollect), "ack=%u ", ack);

    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OFFX2, TH_OFF(tp), hlen, TH_RESV(tp));

    flags = GET_U_1(tp->th_flags);
    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_FLAGS, bittok2str(tcp_flag_values, "none", flags), flags);

    nd_filling_l2(ifn, su, 0, 2, LAYER_4_TCP_WIN, win);
    snprintf(icollect + strlen(icollect), 256 - strlen(icollect), "win=%hu ", win);

    if (ndo->ndo_vflag && !ndo->ndo_Kflag && !fragmented) {
        /* Check the checksum, if possible. */
        uint16_t sum, tcp_sum;
        if (IP_V(ip) == 4) {
            if (ND_TTEST_LEN(tp->th_sport, length)) {
                sum = tcp_cksum(ndo, ip, tp, length);
                tcp_sum = GET_BE_U_2(tp->th_sum);
                if (sum != 0) {
                    nd_filling_l2(ifn, su, 0, 2, 
                        LAYER_4_TCP_CHECKSUM "(incorrect -> 0x%04x)", tcp_sum,
                        in_cksum_shouldbe(tcp_sum, sum));
                }
                else {
                    nd_filling_l2(ifn, su, 0, 2, LAYER_4_TCP_CHECKSUM, tcp_sum);
                }
            }
        }
        else if (IP_V(ip) == 6) {
            if (ND_TTEST_LEN(tp->th_sport, length)) {
                sum = tcp6_cksum(ndo, ip6, tp, length);
                tcp_sum = GET_BE_U_2(tp->th_sum);
                if (sum != 0) {
                    nd_filling_l2(ifn, su, 0, 2,
                        LAYER_4_TCP_CHECKSUM "(incorrect -> 0x%04x)", tcp_sum,
                        in_cksum_shouldbe(tcp_sum, sum)
                    );
                }
                else {
                    nd_filling_l2(ifn, su, 0, 2, LAYER_4_TCP_CHECKSUM, tcp_sum);
                }
            }
        }
    }

    nd_filling_l2(ifn, su, 0, 2, LAYER_4_TCP_URP, urp);

    length -= hlen;

    snprintf(icollect + strlen(icollect), 256 - strlen(icollect), "Len=%hu ", length);

    /*
     * Handle any options.
     */
    if (hlen > sizeof(*tp)) {
        const u_char *cp;
        u_int i, opt, datalen;
        u_int len;

        hlen -= sizeof(*tp);
        cp = (const u_char *)tp + sizeof(*tp);

        while (hlen > 0) {
            opt = GET_U_1(cp);
            cp++;
            if (ZEROLENOPT(opt)) {
                len = 1;
            }
            else {
                len = GET_U_1(cp);
                cp++; /* total including type, len */
                if (len < 2 || len > hlen)
                    goto bad;
                --hlen; /* account for length byte */
            }
            --hlen; /* account for type byte */
            datalen = 0;

            /* Bail if "l" bytes of data are not left or were not captured  */
            #define LENCHECK(l) { if ((l) > hlen) goto bad; ND_TCHECK_LEN(cp, l); }

            switch (opt) {
                case TCPOPT_MAXSEG:
                    datalen = 2;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE,
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    nd_filling_l2(ifn, su, 0, 2, "mss value: %u", GET_BE_U_2(cp));
                    snprintf(icollect + strlen(icollect), 256 - strlen(icollect), "MSS=%hu ", GET_BE_U_2(cp));
                    break;
                case TCPOPT_WSCALE:
                    datalen = 1;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE,
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    nd_filling_l2(ifn, su, 0, 1, "shift count: %u (multiply by %u)",
                        GET_U_1(cp), (1 << GET_U_1(cp)));
                    break;
                case TCPOPT_SACK:
                    datalen = len - 2;
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE,
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    if (datalen % 8 != 0) {
                        nd_filling_l2(ifn, su, 0, datalen, "value: invalid");
                    }
                    else {
                        uint32_t s, e;
                        for (i = 0; i < datalen; i += 8) {
                            LENCHECK(i + 4);
                            s = GET_BE_U_4(cp + i);
                            LENCHECK(i + 8);
                            e = GET_BE_U_4(cp + i + 4);
                            nd_filling_l2(ifn, su, 0, 8, "left edge: %u, right edge: %u", s, e);
                        }
                    }
                    break;
                case TCPOPT_CC:
                case TCPOPT_CCNEW:
                case TCPOPT_CCECHO:
                case TCPOPT_ECHO:
                case TCPOPT_ECHOREPLY:
                    /*
                     * those options share their semantics.
                     * fall through
                     */
                    datalen = 4;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    nd_filling_l2(ifn, su, 0, 4, "value: %u", GET_BE_U_4(cp));
                    break;
                case TCPOPT_TIMESTAMP:
                    datalen = 8;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    nd_filling_l2(ifn, su, 0, 8, 
                        "option timestamp value: %u, timestamp echo reply: %u", GET_BE_U_4(cp), GET_BE_U_4(cp + 4));
                    break;
                case TCPOPT_SIGNATURE:
                    datalen = TCP_SIGLEN;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    char buffer[48] = {0};
                    for (i = 0; i < TCP_SIGLEN; ++i) {
                        snprintf(buffer + strlen(buffer), (48 - strlen(buffer)), "%02x", GET_U_1(cp + i));
                    }
                    nd_filling_l2(ifn, su, 0, datalen, "md5 digest: %s", buffer);
                case TCPOPT_SCPS:
                    datalen = 2;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    nd_filling_l2(ifn, su, 0, datalen, "flags: cap %02x id %u", GET_U_1(cp), GET_U_1(cp + 1));
                    break;
                case TCPOPT_TCPAO:
                    datalen = len - 2;
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    /* RFC 5925 Section 2.2:
                     * "The Length value MUST be greater than or equal to 4."
                     * (This includes the Kind and Length fields already processed
                     * at this point.)
                     */
                    if (datalen < 2) {
                        nd_filling_l2(ifn, su, 0, datalen, "value: invalid");
                    }
                    else {
                        char buffer[80] = {0};
                        LENCHECK(1);
                        nd_filling_l2(ifn, su, 0, 1, "keyid: %u", GET_U_1(cp));
                        LENCHECK(2);
                        nd_filling_l2(ifn, su, 0, 1, "rnextkeyid: %u", GET_U_1(cp + 1));
                        if (datalen > 2) {
                            snprintf(buffer + strlen(buffer), 80 - strlen(buffer), "mac 0x");
                            for (i = 2; i < datalen; i++) {
                                LENCHECK(i + 1);
                                snprintf(buffer + strlen(buffer), 80 - strlen(buffer), "%02x", GET_U_1(cp + i));
                            }
                            nd_filling_l2(ifn, su, 0, datalen - 2, "%s", buffer);
                        }
                    }
                    break;
                case TCPOPT_EOL:
                case TCPOPT_NOP:
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    break;
                case TCPOPT_SACKOK:
                    /*
                    * Nothing interesting.
                    * fall through
                    */
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    break;
                case TCPOPT_UTO:
                    datalen = 2;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    utoval = GET_BE_U_2(cp);
                    if (utoval & 0x0001) {
                        nd_filling_l2(ifn, su, 0, datalen, 
                            "granularity: minutes, user timeout: %u (%.3f seconds)", 
                            (utoval >> 1), ((utoval >> 1) * 60.0));
                    }
                    else {
                        utoval >>= 1;
                        nd_filling_l2(ifn, su, 0, datalen,
                            "granularity: milliseconds, user timeout: %u (%.3f seconds)", 
                            utoval, (utoval / 1000.0));
                    }
                    break;
                case TCPOPT_MPTCP:
                {
                    const u_char *snapend_save;
                    int ret;

                    datalen = len - 2;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE, 
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);

                    /* Update the snapend to the end of the option
                     * before calling mptcp_print(). Some options
                     * (MPTCP or others) may be present after a
                     * MPTCP option. This prevents that, in
                     * mptcp_print(), the remaining length < the
                     * remaining caplen.
                     */
                    snapend_save = ndo->ndo_snapend;
                    ndo->ndo_snapend = ND_MIN(cp - 2 + len, ndo->ndo_snapend);
                    ret = mptcp_print(ndo, ifn, su, cp - 2, len, flags);
                    ndo->ndo_snapend = snapend_save;
                    if (!ret) {
                        if (datalen > 0) {
                            nd_filling_l2(ifn, su, 0, datalen, "value: invalid");
                        }
                        goto bad;
                    }
                    break;
                }
                case TCPOPT_FASTOPEN:
                    datalen = len - 2;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE,
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    if (datalen == 0) {
                        ifn->idx -= 1;
                        nd_filling_l2(ifn, su, 0, 1, "No Cookie present (TFO request)");
                    }
                    else {
                        if (datalen % 2 != 0 || datalen < 4 || datalen > 16) {
                            nd_filling_l2(ifn, su, 0, datalen, "invalid");
                        }
                        else {
                            int i = 0;
                            char buffer[64] = {0};
                            snprintf(buffer, 64, "%s", "cookie: ");
                            for (i = 0; i < datalen; ++i) {
                                snprintf(buffer + strlen(buffer), 64 - strlen(buffer), "%02x", GET_U_1(cp + i));
                            }
                            nd_filling_l2(ifn, su, 0, datalen, "%s", buffer);
                        }
                    }
                    break;
                case TCPOPT_EXPERIMENT2:
                    #if 0
                    datalen = len - 2;
                    LENCHECK(datalen);
                    if (datalen < 2)
                        goto bad;
                    /* RFC6994 */
                    magic = GET_BE_U_2(cp);
                    ND_PRINT("-");

                    switch (magic)
                    {
                        case 0xf989: /* TCP Fast Open RFC 7413 */
                            print_tcp_fastopen_option(ndo, cp + 2, datalen - 2, TRUE);
                            break;

                        default:
                            /* Unknown magic number */
                            ND_PRINT("%04x", magic);
                            break;
                    }
                    #endif
                    datalen = len - 2;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE,
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    if (datalen < 2)
                        goto bad;
                    nd_filling_l2(ifn, su, 0, datalen, "not supported temporarily");
                    break;
                default:
                    datalen = len - 2;
                    LENCHECK(datalen);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_TYPE,
                        tok2str(tcp_option_long_values, "unknown-%u", opt), opt);
                    nd_filling_l2(ifn, su, 0, 1, LAYER_4_TCP_OPTION_LEN, len);
                    nd_filling_l2(ifn, su, 0, datalen, "value: not supported temporarily");
                    break;
            }
            /* Account for data printed */
            cp += datalen;
            hlen -= datalen;

            /* Check specification against observed length */
            ++datalen; /* option octet */
            if (!ZEROLENOPT(opt))
                ++datalen; /* size octet */
            if (datalen != len) {
                //ND_PRINT("[len %u]", len);
            }
            //ch = ',';
            if (opt == TCPOPT_EOL)
                break;
        }
    }

    if (length == 0) {
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        #if 0
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "sport %u -> dport %u, %s, win %u",
            sport, dport, bittok2str(tcp_flag_values, "none", flags), win);
        #endif
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "%s", icollect);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        RVoid();
    }

    /*
     * Decode payload if necessary.
     */
    header_len = TH_OFF(tp) * 4;

    /*
     * Do a bounds check before decoding the payload.
     * At least the header data is required.
     */
    if (!ND_TTEST_LEN(bp, header_len))
    {
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        nd_trunc_longjmp(ndo);
    }

    bp += header_len;
    if ((flags & TH_RST) && ndo->ndo_vflag)
    {
        char buffer[80] = {0};
        print_tcp_rst_data(ndo, bp, length, buffer);
        snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
        #if 0
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "sport %u -> dport %u, %s, win %u, %s",
            sport, dport, bittok2str(tcp_flag_values, "none", flags), win, buffer);
        #endif
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "%s", icollect);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        RVoid();
    }

    #if 0
    if (ndo->ndo_packettype)
    {
        switch (ndo->ndo_packettype)
        {
        case PT_ZMTP1:
            zmtp1_print(ndo, bp, length);
            break;
        case PT_RESP:
            resp_print(ndo, bp, length);
            break;
        case PT_DOMAIN:
            /* over_tcp: TRUE, is_mdns: FALSE */
            domain_print(ndo, bp, length, TRUE, FALSE);
            break;
        }
        RVoid();
    }
    #endif

    #if 0
    if (IS_SRC_OR_DST_PORT(FTP_PORT)) {
        ND_PRINT(": ");
        ftp_print(ndo, bp, length);
    } else if (IS_SRC_OR_DST_PORT(SSH_PORT)) {
        ssh_print(ndo, bp, length);
    } else if (IS_SRC_OR_DST_PORT(TELNET_PORT)) {
        telnet_print(ndo, bp, length);
    }      
    #endif

    // add else
    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    #if 0
    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "sport %u -> dport %u, %s, win %u",
             sport, dport, bittok2str(tcp_flag_values, "none", flags), win);
    #endif
    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "%s", icollect);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    RVoid();

bad:
    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "bad option length");
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
    RVoid();

trunc:
    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, " truncated (invalid)");
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
    RVoid();
}