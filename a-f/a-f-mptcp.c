
#include "ndo.h"
#include "header.h"
#include "a-f-ip.h"
#include "a-f-ip6.h"
#include "a-f-tcp.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"
#include "a-f-addrtoname.h"

#define MPTCP_SUB_CAPABLE 0x0
#define MPTCP_SUB_JOIN 0x1
#define MPTCP_SUB_DSS 0x2
#define MPTCP_SUB_ADD_ADDR 0x3
#define MPTCP_SUB_REMOVE_ADDR 0x4
#define MPTCP_SUB_PRIO 0x5
#define MPTCP_SUB_FAIL 0x6
#define MPTCP_SUB_FCLOSE 0x7

static int
dummy_print(ndo_t *ndo _U_, u_int *pidx, void *infonode, void *psu,
            const u_char *opt _U_, u_int opt_len _U_, u_char flags _U_);

static int
mp_capable_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags);

static int
mp_join_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags);

static int
mp_dss_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags);

static int
add_addr_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags _U_);

static int
remove_addr_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags _U_);

static int
mp_prio_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags _U_);

static int
mp_fail_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags _U_);

static int
mp_fast_close_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
            const u_char *opt, u_int opt_len, u_char flags _U_);

static const struct
{
    const char *name;
    int (*print)(ndo_t *, u_int *, void *, void *, const u_char *, u_int, u_char);
} mptcp_options[] = {
    {"mptcp capable", mp_capable_print},
    {"mptcp join", mp_join_print},
    {"mptcp dss (data sequence signal)", mp_dss_print},
    {"mptcp add address", add_addr_print},
    {"mptcp remove address", remove_addr_print},
    {"mptcp priority", mp_prio_print},
    {"mptcp fail", mp_fail_print},
    {"mptcp fast close", mp_fast_close_print},
    {"unknown", dummy_print},
};

struct mptcp_option
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub_etc; /* subtype upper 4 bits, other stuff lower 4 bits */
};

#define MPTCP_OPT_SUBTYPE(sub_etc) (((sub_etc) >> 4) & 0xF)

struct mp_capable
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub_ver;
    nd_uint8_t flags;
    nd_uint64_t sender_key;
    nd_uint64_t receiver_key;
};

#define MP_CAPABLE_OPT_VERSION(sub_ver) (((sub_ver) >> 0) & 0xF)
#define MP_CAPABLE_C 0x80
#define MP_CAPABLE_S 0x01

struct mp_join
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub_b;
    nd_uint8_t addr_id;
    union
    {
        struct
        {
            nd_uint32_t token;
            nd_uint32_t nonce;
        } syn;
        struct
        {
            nd_uint64_t mac;
            nd_uint32_t nonce;
        } synack;
        struct
        {
            nd_byte mac[20];
        } ack;
    } u;
};

#define MP_JOIN_B 0x01

struct mp_dss
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub;
    nd_uint8_t flags;
};

#define MP_DSS_F 0x10
#define MP_DSS_m 0x08
#define MP_DSS_M 0x04
#define MP_DSS_a 0x02
#define MP_DSS_A 0x01

static const struct tok mptcp_addr_subecho_bits[] = {
    {0x6, "v0-ip6"},
    {0x4, "v0-ip4"},
    {0x1, "v1-echo"},
    {0x0, "v1"},
    {0, NULL}
};

struct mp_add_addr
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub_echo;
    nd_uint8_t addr_id;
    union
    {
        struct
        {
            nd_ipv4 addr;
            nd_uint16_t port;
            nd_uint64_t mac;
        } v4;
        struct
        {
            nd_ipv4 addr;
            nd_uint64_t mac;
        } v4np;
        struct
        {
            nd_ipv6 addr;
            nd_uint16_t port;
            nd_uint64_t mac;
        } v6;
        struct
        {
            nd_ipv6 addr;
            nd_uint64_t mac;
        } v6np;
    } u;
};

struct mp_remove_addr
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub;
    /* list of addr_id */
    nd_uint8_t addrs_id[1];
};

struct mp_fail
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub;
    nd_uint8_t resv;
    nd_uint64_t data_seq;
};

struct mp_close
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub;
    nd_uint8_t rsv;
    nd_byte key[8];
};

struct mp_prio
{
    nd_uint8_t kind;
    nd_uint8_t len;
    nd_uint8_t sub_b;
    nd_uint8_t addr_id;
};

#define MP_PRIO_B 0x01

static int
dummy_print(ndo_t *ndo _U_, u_int *pidx, void *infonode, void *psu,
            const u_char *opt _U_, u_int opt_len _U_, u_char flags _U_)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    RInt(1);
}

static int
mp_capable_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
                 const u_char *opt, u_int opt_len, u_char flags)
{
    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    const struct mp_capable *mpc = (const struct mp_capable *)opt;
    uint8_t version;

    if (!(opt_len == 12 || opt_len == 4 || opt_len == 20 || opt_len == 22)) {
        RInt(0);
    }

    if (!((opt_len == 12 || opt_len == 4) && flags & TH_SYN) &&
        !((opt_len == 20 || opt_len == 22) && (flags & (TH_SYN | TH_ACK)) ==
                                                  TH_ACK)) {
        RInt(0);
    }
    version = MP_CAPABLE_OPT_VERSION(GET_U_1(mpc->sub_ver));

    if (!(version == 0 || version == 1)) {
        RInt(0);
    }

    u_int subtype = (GET_U_1(mpc->sub_ver) >> 4) & 0xf;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
                mptcp_options[subtype].name, subtype);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "version: %u", version);
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "flags: 0x%x", flags);
    idx = idx + 1;

    if (opt_len == 12 || opt_len >= 20)
    {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
            "sender key: 0x%" PRIx64, GET_BE_U_8(mpc->sender_key));
        idx = idx + 8;
        if (opt_len >= 20) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "receiver key: 0x%" PRIx64, GET_BE_U_8(mpc->receiver_key));
            idx = idx + 8;
        }
    }

    *pidx = idx;

    RInt(1);
}

static int
mp_join_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
              const u_char *opt, u_int opt_len, u_char flags)
{
    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    const struct mp_join *mpj = (const struct mp_join *)opt;
    u_int subtype = (GET_U_1(mpj->sub_b) >> 4) & 0xf;

    if (!(opt_len == 12 || opt_len == 16 || opt_len == 24)) {
        RInt(0);
    }

    if (!(opt_len == 12 && (flags & TH_SYN)) &&
        !(opt_len == 16 && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) &&
        !(opt_len == 24 && (flags & TH_ACK))) {
        RInt(0);
    }

    if (opt_len != 24)
    {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
                mptcp_options[subtype].name, subtype);
        
        if (GET_U_1(mpj->sub_b) & MP_JOIN_B) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                "flags: 0x%x (backup path: yes)", GET_U_1(mpj->sub_b) & 0xf);
        }
        idx = idx + 1;
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                "address id: %u", GET_U_1(mpj->addr_id));
        idx = idx + 1;
    }
    else {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
                mptcp_options[subtype].name, subtype);
        idx = idx + 1;
        idx = idx + 1; // address id don't show 
    }

    switch (opt_len)
    {
        case 12: /* SYN */
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
                "token: 0x%x", GET_BE_U_4(mpj->u.syn.token));
            idx = idx + 4;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
                "nonce: 0x%x", GET_BE_U_4(mpj->u.syn.nonce));
            idx = idx + 4;
            break;
        case 16: /* SYN/ACK */
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "hmac: 0x%" PRIx64, GET_BE_U_8(mpj->u.synack.mac));
            idx = idx + 8;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
                "nonce: 0x%x", GET_BE_U_4(mpj->u.synack.nonce));
            idx = idx + 4;
            break;
        case 24:
        { /* ACK */
            size_t i;
            char buffer[64] = {0};
            snprintf(buffer + strlen((const char *)buffer), 64 - strlen((const char *)buffer), "%s", "hmac 0x");
            for (i = 0; i < sizeof(mpj->u.ack.mac); ++i) {
                snprintf(buffer + strlen((const char *)buffer), 64 - strlen((const char *)buffer), "%02x", mpj->u.ack.mac[i]);
            }
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 20 - 1, 
                "%s", buffer);
            idx = idx + 20;
        }
        default:
            break;
    }

    *pidx = idx;

    RInt(1);
}

static int
mp_dss_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
             const u_char *opt, u_int opt_len, u_char flags)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    const struct mp_dss *mdss = (const struct mp_dss *)opt;
    uint8_t mdss_flags;
    u_int tmp_len = opt_len;
    char buffer[32] = {0};

    u_int subtype = (GET_U_1(mdss->sub) >> 4) & 0xf;

    /* We need the flags, at a minimum. */
    if (opt_len < 4) {
        RInt(0);
    }

    if (flags & TH_SYN) {
        RInt(0);
    }

    mdss_flags = GET_U_1(mdss->flags);

    tmp_len -= 4;
    if (mdss_flags & MP_DSS_A) {
        snprintf(buffer + strlen((const char *)buffer), 32 - strlen((const char *)buffer), "%s", "A ");

        if (mdss_flags & MP_DSS_a)
        {
            snprintf(buffer + strlen((const char *)buffer), 32 - strlen((const char *)buffer), "%s", "a ");
            if (tmp_len < 8) {
                RInt(0);
            }
            tmp_len -= 8;
        }
        else {
            if (tmp_len < 4) {
                RInt(0);
            }
            tmp_len -= 4;
        }
    }
    if (mdss_flags & MP_DSS_M) {
        snprintf(buffer + strlen((const char *)buffer), 32 - strlen((const char *)buffer), "%s", "M ");
        if (mdss_flags & MP_DSS_m) {
            snprintf(buffer + strlen((const char *)buffer), 32 - strlen((const char *)buffer), "%s", "m ");
            if (tmp_len < 8) {
                RInt(0);
            }
            tmp_len -= 8;
        }
        else {
            if (tmp_len < 4) {
                RInt(0);
            }
            tmp_len -= 4;
        }
        if (tmp_len < 4) {
            RInt(0);
        }
        tmp_len -= 4;
        if (tmp_len < 2) {
            RInt(0);
        }
        tmp_len -= 2;
        if (tmp_len >= 2) {
            tmp_len -= 2;
        }
    }

    if (tmp_len != 0) {
        RInt(0);
    }

    if (mdss_flags & MP_DSS_F) {
        snprintf(buffer + strlen((const char *)buffer), 32 - strlen((const char *)buffer), "%s", "F ");
    }

    
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
            mptcp_options[subtype].name, subtype);
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "flags: 0x%x (%s set)",
            mdss_flags, buffer);
    idx = idx + 1;

    opt += 4;
    opt_len -= 4;

    if (mdss_flags & MP_DSS_A)
    {
        /*
         * If the a flag is set, we have an 8-byte ack; if it's
         * clear, we have a 4-byte ack.
         */
        if (mdss_flags & MP_DSS_a)
        {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "data ack: %" PRIu64, GET_BE_U_8(opt));
            idx = idx + 8;
            opt += 8;
            opt_len -= 8;
        }
        else
        {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
                "data ack: %u", GET_BE_U_4(opt));
            idx = idx + 4;
            opt += 4;
            opt_len -= 4;
        }
    }

    if (mdss_flags & MP_DSS_M)
    {
        /*
         * Data Sequence Number (DSN), Subflow Sequence Number (SSN),
         * Data-Level Length present, and Checksum possibly present.
         */
        /*
         * If the m flag is set, we have an 8-byte NDS; if it's clear,
         * we have a 4-byte DSN.
         */
        if (mdss_flags & MP_DSS_m)
        {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "dsn: %" PRIu64, GET_BE_U_8(opt));
            idx = idx + 8;
            opt += 8;
            opt_len -= 8;
        }
        else
        {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
                "dsn: %u", GET_BE_U_4(opt));
            idx = idx + 4;
            opt += 4;
            opt_len -= 4;
        }

        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
            "subflow seq: %u", GET_BE_U_4(opt));
        idx = idx + 4;
        opt += 4;
        opt_len -= 4;

        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
            "data-level length: %u", GET_BE_U_2(opt));
        idx = idx + 2;
        opt += 2;
        opt_len -= 2;

        /*
         * The Checksum is present only if negotiated.
         * If there are at least 2 bytes left, process the next 2
         * bytes as the Checksum.
         */
        if (opt_len >= 2)
        {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                "checksum: %u", GET_BE_U_2(opt));
            idx = idx + 2;
            opt_len -= 2;
        }
    }

    *pidx = idx;

    RInt(1);
}

static int
add_addr_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
               const u_char *opt, u_int opt_len, u_char flags _U_)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    const struct mp_add_addr *add_addr = (const struct mp_add_addr *)opt;

    if (!(opt_len == 8 || opt_len == 10 || opt_len == 16 || opt_len == 18 ||
          opt_len == 20 || opt_len == 22 || opt_len == 28 || opt_len == 30)) {
        RInt(0);
    }

    u_int flag = GET_U_1(add_addr->sub_echo) & 0xF;
    if (!(flag == 0x0 || flag == 0x1 || flag == 0x4 || flag == 0x6)) {
        RInt(0);
    }

    u_int subtype = (GET_U_1(add_addr->sub_echo) >> 4) & 0xf;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u), flags: %s",
            mptcp_options[subtype].name, subtype, 
            tok2str(mptcp_addr_subecho_bits, "[bad version/echo]", flag)
    );
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
            "address id: %u", GET_U_1(add_addr->addr_id));
    idx = idx + 1;

    if (opt_len == 8 || opt_len == 10 || opt_len == 16 || opt_len == 18)
    {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
            "address (ipv4): %s", GET_IPADDR_STRING(add_addr->u.v4.addr));
        idx = idx + 4;
        if (opt_len == 10 || opt_len == 18) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                "port (ipv4): %u", GET_BE_U_2(add_addr->u.v4.port));
            idx = idx + 2;
        }
        if (opt_len == 16) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "hardware id (ipv4): 0x%" PRIx64, GET_BE_U_8(add_addr->u.v4np.mac));
            idx = idx + 8;
        }
        if (opt_len == 18) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "hardware id ipv4): 0x%" PRIx64, GET_BE_U_8(add_addr->u.v4.mac));
            idx = idx + 8;
        }
    }

    if (opt_len == 20 || opt_len == 22 || opt_len == 28 || opt_len == 30)
    {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 16 - 1, 
            "address (ipv6): %s", GET_IP6ADDR_STRING(add_addr->u.v6.addr));
        idx = idx + 16;
        if (opt_len == 22 || opt_len == 30) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                "port (ipv6): %u", GET_BE_U_2(add_addr->u.v6.port));
            idx = idx + 2;
        }
        if (opt_len == 28) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "hardware id (ipv6): 0x%" PRIx64, GET_BE_U_8(add_addr->u.v6np.mac));
            idx = idx + 8;
        }
        if (opt_len == 30) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 8 - 1, 
                "hardware id (ipv6): 0x%" PRIx64, GET_BE_U_8(add_addr->u.v6.mac));
            idx = idx + 8;
        }
    }

    *pidx = idx;

    RInt(1);
}

static int
remove_addr_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
                  const u_char *opt, u_int opt_len, u_char flags _U_)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    const struct mp_remove_addr *remove_addr = (const struct mp_remove_addr *)opt;
    u_int i;

    if (opt_len < 4) {
        RInt(0);
    }

    u_int subtype = (GET_U_1(remove_addr->sub) >> 4) & 0xf;
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
            mptcp_options[subtype].name, subtype);
    idx = idx + 1;

    opt_len -= 3;
    
    for (i = 0; i < opt_len; i++) {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "address id: %u",
            GET_U_1(remove_addr->addrs_id[i]));
        idx = idx + 1;
    }

    *pidx = idx;

    RInt(1);
}

static int
mp_prio_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
              const u_char *opt, u_int opt_len, u_char flags _U_)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    const struct mp_prio *mpp = (const struct mp_prio *)opt;
    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    if (opt_len != 3 && opt_len != 4) {
        RInt(0);
    }

    u_int subtype = (GET_U_1(mpp->sub_b) >> 4) & 0xf;
    u_int flag = (GET_U_1(mpp->sub_b)) & 0xf;

    if (opt_len == 3) {
        if (flag < 0 || flag > 1) {
            RInt(0);
        }
    }
    if (opt_len == 4) {
        if (flag < 2 || flag > 3) {
            RInt(0);
        }
    }
    

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
            mptcp_options[subtype].name, subtype);

    if (opt_len == 3) {
        if (flag == 0) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                "flags: backup path: false, dddress id present: false");
        }
        if (flag == 1) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                "flags: backup path: ture, dddress id present: false");
        }
        idx = idx + 1;
        *pidx = idx;
        RInt(1);
    }
    else if(opt_len == 4) {
        if (flag == 2) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                "flags: backup path: false, dddress id present: true");
        }
        if (flag == 3) {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                "flags: backup path: ture, dddress id present: true");
        }
        idx = idx + 1;
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
            "address id: %u", GET_U_1(mpp->addr_id));
        idx = idx + 1;
        *pidx = idx;
        RInt(1);
    }

    RInt(1);
}

static int
mp_fail_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
              const u_char *opt, u_int opt_len, u_char flags _U_)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    struct mp_fail *mpfail = (struct mp_fail *)opt;

    if (opt_len != 12)
    {
        RInt(0);
    }

    u_int subtype = (GET_U_1(mpfail->sub) >> 4) & 0xf;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
                mptcp_options[subtype].name, subtype);
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "reserved: %u", 
        GET_U_1(mpfail->resv));
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + opt_len - 4 - 1,
            " seq %" PRIu64, GET_BE_U_8(opt + 4));
    idx = idx + opt_len - 4;

    *pidx = idx;

    return 1;
}

static int
mp_fast_close_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
                    const u_char *opt, u_int opt_len, u_char flags _U_)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx,
       infonode, psu, opt, opt_len, flags);

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    struct mp_close *mpclose = (struct mp_close *)opt;

    if (opt_len != 12) {
        RInt(0);
    }

    u_int subtype = (GET_U_1(mpclose->sub) >> 4) & 0xf;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: %s (%u)",
                mptcp_options[subtype].name, subtype);
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "reserved: %u", 
        GET_U_1(mpclose->rsv));
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + opt_len - 4 - 1,
            "key 0x%" PRIx64, GET_BE_U_8(opt + 4));
    idx = idx + opt_len - 4;

    *pidx = idx;

    RInt(1);
}

#if 0
static const struct
{
    const char *name;
    int (*print)(ndo_t *, u_int *, void *, void *, const u_char *, u_int, u_char);
} mptcp_options[] = {
    {"capable", mp_capable_print},
    {"join", mp_join_print},
    {"dss", mp_dss_print},
    {"add-addr", add_addr_print},
    {"rem-addr", remove_addr_print},
    {"prio", mp_prio_print},
    {"fail", mp_fail_print},
    {"fast-close", mp_fast_close_print},
    {"unknown", dummy_print},
};
#endif

int mptcp_print(ndo_t *ndo, u_int *pidx, void *infonode, void *psu,
                const u_char *cp, u_int len, u_char flags)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %p, %u, %u)", __func__, ndo, pidx, *pidx, 
        infonode, psu, cp, len, flags);

    const struct mptcp_option *opt;
    u_int subtype;

    u_int idx = *pidx;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = (l1l2_node_t *)psu;

    ndo->ndo_protocol = "mptcp";
    if (len < 3) {
        RInt(0);
    }

    opt = (const struct mptcp_option *)cp;
    subtype = MPTCP_OPT_SUBTYPE(GET_U_1(opt->sub_etc));

    if (subtype < 0 || subtype > MPTCP_SUB_FCLOSE)
    {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, "subtype: unknown (%u)", 
            subtype);
        idx = idx + 1;
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + len - 3 - 1, 
            "invaild value");
        idx = idx + len - 3;
        *pidx = idx;
        RInt(1);
    }

    subtype = ND_MIN(subtype, MPTCP_SUB_FCLOSE + 1);

    int ret = mptcp_options[subtype].print(ndo, pidx, infonode, psu, cp, len, flags);

    RInt(ret);
}