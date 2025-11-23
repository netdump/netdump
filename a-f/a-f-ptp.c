
#include "header.h"
#include "a-f-extract.h"


#if 0
/*
 * PTP header
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  R  | |msgtype|  version      |  Msg Len                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  domain No    | rsvd1         |   flag Field                  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        Correction NS                          |
 *    +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                               |      Correction Sub NS        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           Reserved2                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        Clock Identity                         |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |         Port Identity         |         Sequence ID           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |    control    |  log msg int  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     0                   1                   2                   3
 *
 * Announce Message (msg type=0xB)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                            Seconds                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Nano Seconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     Origin Cur UTC Offset     |     Reserved    | GM Prio 1   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |GM Clock Class | GM Clock Accu |        GM Clock Variance      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   GM Prio 2   |                                               |
 *    +-+-+-+-+-+-+-+-+                                               +
 *    |                      GM Clock Identity                        |
 *    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |               |         Steps Removed           | Time Source |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     0                   1                   2                   3
 *
 * Sync Message (msg type=0x0)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                            Seconds                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Nano Seconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Delay Request Message (msg type=0x1)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |             Origin Time Stamp Seconds                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Nano Seconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Followup Message (msg type=0x8)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |      Precise Origin Time Stamp Seconds                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Nano Seconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Delay Resp Message (msg type=0x9)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                            Seconds                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Nano Seconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          Port Identity        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  PDelay Request Message (msg type=0x2)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                    Origin Time Stamp Seconds                  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                  Origin Time Stamp Nano Seconds               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          Port Identity        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  PDelay Response Message (msg type=0x3)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |     Request receipt Time Stamp Seconds                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Nano Seconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Requesting Port Identity      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  PDelay Resp Follow up Message (msg type=0xA)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |      Response Origin Time Stamp Seconds                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Nano Seconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Requesting Port Identity      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Signaling Message (msg type=0xC)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    | Requesting Port Identity      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Management Message (msg type=0xD)
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                    | Requesting Port Identity      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Start Bndry Hps| Boundary Hops | flags         | Reserved      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
#endif


/* Values from IEEE1588-2008: 13.3.2.2 messageType (Enumeration4) */
#define M_SYNC                              0x0
#define M_DELAY_REQ                         0x1
#define M_PDELAY_REQ                        0x2
#define M_PDELAY_RESP                       0x3
#define M_FOLLOW_UP                         0x8
#define M_DELAY_RESP                        0x9
#define M_PDELAY_RESP_FOLLOW_UP             0xA
#define M_ANNOUNCE                          0xB
#define M_SIGNALING                         0xC
#define M_MANAGEMENT                        0xD

static const struct tok ptp_msg_type[] = {
    { M_SYNC, "sync msg"},
    { M_DELAY_REQ, "delay req msg"},
    { M_PDELAY_REQ, "peer delay req msg"},
    { M_PDELAY_RESP, "peer delay resp msg"},
    { M_FOLLOW_UP, "follow up msg"},
    { M_DELAY_RESP, "delay resp msg"},
    { M_PDELAY_RESP_FOLLOW_UP, "pdelay resp fup msg"},
    { M_ANNOUNCE, "announce msg"},
    { M_SIGNALING, "signaling msg"},
    { M_MANAGEMENT, "management msg"},
    { 0, NULL}
};


/* Values from IEEE1588-2008: 13.3.2.10 controlField (UInteger8) */
/*
 * The use of this field by the receiver is deprecated.
 * NOTE-This field is provided for compatibility with hardware designed
 * to conform to version 1 of this standard.
 */
#define C_SYNC              0x0
#define C_DELAY_REQ         0x1
#define C_FOLLOW_UP         0x2
#define C_DELAY_RESP        0x3
#define C_MANAGEMENT        0x4
#define C_OTHER             0x5

static const struct tok ptp_control_field[] = {
    { C_SYNC, "Sync"},
    { C_DELAY_REQ, "Delay_Req"},
    { C_FOLLOW_UP, "Follow_Up"},
    { C_DELAY_RESP, "Delay_Resp"},
    { C_MANAGEMENT, "Management"},
    { C_OTHER, "Other"},
    { 0, NULL}
};

#define PTP_TRUE 1
#define PTP_FALSE !PTP_TRUE

#define PTP_HDR_LEN             0x22

/* mask based on the first byte */
#define PTP_MAJOR_VERS_MASK     0x0F
#define PTP_MINOR_VERS_MASK     0xF0
#define PTP_MAJOR_SDO_ID_MASK   0xF0
#define PTP_MSG_TYPE_MASK       0x0F

/*mask based 2byte */
#define PTP_DOMAIN_MASK         0xFF00
#define PTP_RSVD1_MASK          0xFF
#define PTP_CONTROL_MASK        0xFF
#define PTP_LOGMSG_MASK         0xFF

/* mask based on the flags 2 bytes */

#define PTP_L161_MASK               0x1
#define PTP_L1_59_MASK              0x2
#define PTP_UTC_REASONABLE_MASK     0x4
#define PTP_TIMESCALE_MASK          0x8
#define PTP_TIME_TRACABLE_MASK      0x10
#define PTP_FREQUENCY_TRACABLE_MASK 0x20
#define PTP_ALTERNATE_MASTER_MASK   0x100
#define PTP_TWO_STEP_MASK           0x200
#define PTP_UNICAST_MASK            0x400
#define PTP_PROFILE_SPEC_1_MASK     0x1000
#define PTP_PROFILE_SPEC_2_MASK     0x2000
#define PTP_SECURITY_MASK           0x4000
#define PTP_FLAGS_UNKNOWN_MASK      0x18C0

static const struct tok ptp_flag_values[] = {
    { PTP_L161_MASK, "l1 61"},
    { PTP_L1_59_MASK, "l1 59"},
    { PTP_UTC_REASONABLE_MASK, "utc reasonable"},
    { PTP_TIMESCALE_MASK, "timescale"},
    { PTP_TIME_TRACABLE_MASK, "time tracable"},
    { PTP_FREQUENCY_TRACABLE_MASK, "frequency tracable"},
    { PTP_ALTERNATE_MASTER_MASK, "alternate master"},
    { PTP_TWO_STEP_MASK, "two step"},
    { PTP_UNICAST_MASK, "unicast"},
    { PTP_PROFILE_SPEC_1_MASK, "profile specific 1"},
    { PTP_PROFILE_SPEC_2_MASK, "profile specific 2"},
    { PTP_SECURITY_MASK, "security mask"},
    { PTP_FLAGS_UNKNOWN_MASK,  "unknown"},
    {0, NULL}
};

static const char *p_porigin_ts = "preciseOriginTimeStamp";
static const char *p_origin_ts = "originTimeStamp";
static const char *p_recv_ts = "receiveTimeStamp";

#define PTP_VER_1               0x1
#define PTP_VER_2               0x2

#define PTP_UCHAR_LEN       sizeof(uint8_t)
#define PTP_UINT16_LEN      sizeof(uint16_t)
#define PTP_UINT32_LEN      sizeof(uint32_t)
#define PTP_6BYTES_LEN      sizeof(uint32_t) + sizeof(uint16_t)
#define PTP_UINT64_LEN      sizeof(uint64_t)

static void 
ptp_print_timestamp(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, 
        const u_char *bp, u_int *len, const char *stype);

static void
ptp_print_timestamp_identity(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, 
        const u_char *bp, u_int *len, const char *ttype);

static void
ptp_print_announce_msg(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, 
        const u_char *bp, u_int *len);

static void
ptp_print_port_id(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su,
        const u_char *bp, u_int *len);

static void
ptp_print_mgmt_msg(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su,
        const u_char *bp, u_int *len);

#define LAYER_3_PTP_FORMAT                  "%s"
#define LAYER_3_PTP_CONTENT                 "Precision Time Protocol (v2)"
#define LAYER_3_PTP_TS                      "TransportSpecific: %u"
#define LAYER_3_PTP_MT                      "MessageType: %s (%u)"
#define LAYER_3_PTP_VERSION                 "VersionPTP: %u"
#define LAYER_3_PTP_MSGLEN                  "MessageLength: %u"
#define LAYER_3_PTP_DOMAIN                  "DomainNumber: %u"
#define LAYER_3_PTP_RSVD                    "Reserved: %u"
#define LAYER_3_PTP_FLAG_F                  "Flag Field: %s (0x%04x)"
#define LAYER_3_PTP_CNS                     "Correction NS: %06x"
#define LAYER_3_PTP_CNS_SUB                 "Correction Sub NS: %02x"
#define LAYER_3_PTP_CLOCK_ID                "Clock Identity: 0x%x"
#define LAYER_3_PTP_PORT_ID                 "Port Identity: %u"
#define LAYER_3_PTP_SEQ_ID                  "Sequence ID: %u"
#define LAYER_3_PTP_CONTROL                 "Control: %u (%s)"
#define LAYER_3_PTP_LMI                     "Log Message Interval: %u"
#define LAYER_3_PTP_SECS                    "Seconds: %lu (%s)"
#define LAYER_3_PTP_NAOSECS                 "Nanoseconds: %u (%s)"
#define LAYER_3_PTP_PORT_ID_STR             "Port Identity: 0x%x (%s)"
#define LAYER_3_PTP_PORTID                  "Port ID: %u (%s)"
#define LAYER_3_PTP_O_CUR_UTC               "Origin Current UTC: %u (%s)"
#define LAYER_3_PTP_ORIGIN_RSVD             "RSVD: %u (%s)"
#define LAYER_3_PTP_GM_PRIO_1               "GM Priority 1: %u (%s)"
#define LAYER_3_PTP_GM_CLOCK_CLASS          "GM Clock Class: %u (%s)"
#define LAYER_3_PTP_GM_CLOCK_ACCURACY       "GM Clock Accuracy: %u (%s)"
#define LAYER_3_PTP_GM_CLOCK_VARIANCE       "GM Clock Variance: %u (%s)"
#define LAYER_3_PTP_GM_PRIO_2               "GM Priority 2: %u (%s)"
#define LAYER_3_PTP_GM_CLOCK_ID             "GM Clock ID: 0x%x (%s)"
#define LAYER_3_PTP_STEPS_REMOVED           "Steps Removed: %u (%s)"
#define LAYER_3_PTP_TIME_SOURCE             "Time Source: 0x%x (%s)"


static void ptp_print_2(ndo_t *ndo, void *infonode, const u_char *bp, u_int length)
{
    TC("Called { %s(%p, %p, %p, %u)", __func__, ndo, infonode, bp, length);

    u_int len = length;
    uint16_t msg_len, flags, port_id, seq_id;
    uint8_t foct, version, domain_no, msg_type, major_sdo_id, rsvd1, lm_int, control;
    uint64_t ns_corr;
    uint16_t sns_corr;
    uint32_t rsvd2;
    uint64_t clk_id;

    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    foct = GET_U_1(bp);
    major_sdo_id = (foct & PTP_MAJOR_SDO_ID_MASK) >> 4;
    msg_type = foct & PTP_MSG_TYPE_MASK;

    su = nd_filling_l1(ifn, 0, LAYER_3_PTP_FORMAT, LAYER_3_PTP_CONTENT);

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_TS, major_sdo_id);
    ifn->idx -= 1;
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_MT, tok2str(ptp_msg_type, "Reserved", msg_type), msg_type);

    /* version */
    len -= 1; bp += 1; version = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_VERSION, version);

    /* msg length */
    len -= 1; bp += 1; msg_len = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_MSGLEN, msg_len);

    /* domain */
    len -= 2; bp += 2; domain_no = (GET_BE_U_2(bp) & PTP_DOMAIN_MASK) >> 8;
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_DOMAIN, domain_no);

    /* rsvd 1*/
    rsvd1 = GET_BE_U_2(bp) & PTP_RSVD1_MASK;
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_RSVD, rsvd1);

    /* flags */
    len -= 2; bp += 2; flags = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_FLAG_F, bittok2str(ptp_flag_values, "none", flags), flags);

    /* correction NS (48 bits) */
    len -= 2; bp += 2; ns_corr = GET_BE_U_6(bp);
    nd_filling_l2(ifn, su, 0, 6, LAYER_3_PTP_CNS, ns_corr);

    /* correction sub NS (16 bits) */
    len -= 6; bp += 6; sns_corr = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_CNS_SUB, sns_corr);

    /* Reserved 2 */
    len -= 2; bp += 2; rsvd2 = GET_BE_U_4(bp);
    nd_filling_l2(ifn, su, 0, 4, LAYER_3_PTP_RSVD, rsvd2);

    /* clock identity */
    len -= 4; bp += 4; clk_id = GET_BE_U_8(bp);
    nd_filling_l2(ifn, su, 0, 8, LAYER_3_PTP_CLOCK_ID, clk_id);

    /* port identity */
    len -= 8; bp += 8; port_id = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_PORT_ID, port_id);

    /* sequence ID */
    len -= 2; bp += 2; seq_id = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_SEQ_ID, seq_id);

    /* control */
    len -= 2; bp += 2; control = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_CONTROL, 
        control, tok2str(ptp_control_field, "Reserved", control));

    /* log message interval */
    lm_int = GET_BE_U_2(bp) & PTP_LOGMSG_MASK;
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_LMI, lm_int);

    switch (msg_type)
    {
        case M_SYNC:
            ptp_print_timestamp(ndo, ifn, su, bp, &len, p_origin_ts);
            break;
        case M_DELAY_REQ:
            ptp_print_timestamp(ndo, ifn, su, bp, &len, p_origin_ts);
            break;
        case M_PDELAY_REQ:
            ptp_print_timestamp_identity(ndo, ifn, su, bp, &len, p_porigin_ts);
            break;
        case M_PDELAY_RESP:
            ptp_print_timestamp_identity(ndo, ifn, su, bp, &len, p_recv_ts);
            break;
        case M_FOLLOW_UP:
            ptp_print_timestamp(ndo, ifn, su, bp, &len, p_porigin_ts);
            break;
        case M_DELAY_RESP:
            ptp_print_timestamp_identity(ndo, ifn, su, bp, &len, p_recv_ts);
            break;
        case M_PDELAY_RESP_FOLLOW_UP:
            ptp_print_timestamp_identity(ndo, ifn, su, bp, &len, p_porigin_ts);
            break;
        case M_ANNOUNCE:
            ptp_print_announce_msg(ndo, ifn, su, bp, &len);
            break;
        case M_SIGNALING:
            ptp_print_port_id(ndo, ifn, su, bp, &len);
            break;
        case M_MANAGEMENT:
            ptp_print_mgmt_msg(ndo, ifn, su, bp, &len);
            break;
        default:
            break;
    }

    RVoid();
}


/*
 * PTP general message
 */
void ptp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length)
{

    TC("Called { %s(%p, %p, %p, %u)", __func__, ndo, infonode, bp, length);

    u_int major_vers;
    //u_int minor_vers;

    /* In 1588-2019, a minorVersionPTP field has been created in the common PTP
     * message header, from a previously reserved field. Implementations
     * compatible to the 2019 edition shall indicate a versionPTP field value
     * of 2 and minorVersionPTP field value of 1, indicating that this is PTP
     * version 2.1.
     */

    infonode_t *ifn = (infonode_t *)infonode;

    ndo->ndo_protocol = "ptp";

    if (length < PTP_HDR_LEN)
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "length %u < %u (invalid)",
                 length, PTP_HDR_LEN);
        goto invalid;
    }

    major_vers = GET_BE_U_2(bp) & PTP_MAJOR_VERS_MASK;
    //minor_vers = (GET_BE_U_2(bp) & PTP_MINOR_VERS_MASK) >> 4;

    switch (major_vers) 
    {
        case PTP_VER_1:
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "not implemented");
            goto invalid;
            break;
        case PTP_VER_2:
            ptp_print_2(ndo, infonode, bp, length);
            break;
        default:
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "ERROR: unknown-version");
            goto invalid;
            break;
    }   

    RVoid();

invalid:

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    RVoid();
}

static void ptp_print_timestamp(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, 
            const u_char *bp, u_int *len, const char *stype)
{

    TC("Called { %s(%p, %p, %p, %p, %u, %s)", __func__, ndo, ifn, su, bp, *len, stype);

    uint64_t secs;
    uint32_t nsecs;

    /* sec time stamp 6 bytes */
    secs = GET_BE_U_6(bp);
    nd_filling_l2(ifn, su, 0, 6, LAYER_3_PTP_SECS, secs, stype);

    *len -= 6;
    bp += 6;

    /* NS time stamp 4 bytes */
    nsecs = GET_BE_U_4(bp);
    nd_filling_l2(ifn, su, 0, 4, LAYER_3_PTP_NAOSECS, nsecs, stype);

    *len -= 4;
    bp += 4;

    RVoid();
}

static void
ptp_print_timestamp_identity(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su,
            const u_char *bp, u_int *len, const char *ttype)
{
    TC("Called { %s(%p, %p, %p, %p, %u, %s)", __func__, ndo, ifn, su, bp, *len, ttype);

    uint64_t secs;
    uint32_t nsecs;
    uint16_t port_id;
    uint64_t port_identity;

    /* sec time stamp 6 bytes */
    secs = GET_BE_U_6(bp);
    nd_filling_l2(ifn, su, 0, 6, LAYER_3_PTP_SECS, secs, ttype);

    *len -= 6;
    bp += 6;

    /* NS time stamp 4 bytes */
    nsecs = GET_BE_U_4(bp);
    nd_filling_l2(ifn, su, 0, 4, LAYER_3_PTP_NAOSECS, nsecs, ttype);
    
    *len -= 4;
    bp += 4;

    /* port identity*/
    port_identity = GET_BE_U_8(bp);
    nd_filling_l2(ifn, su, 0, 8, LAYER_3_PTP_PORT_ID_STR, port_identity, ttype);
    
    *len -= 8;
    bp += 8;

    /* port id */
    port_id = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_PORTID, port_id, ttype);
    
    *len -= 2;
    bp += 2;

    RVoid();
}

static void
ptp_print_announce_msg(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, 
            const u_char *bp, u_int *len)
{
    TC("Called { %s(%p, %p, %p, %p, %u)", __func__, ndo, ifn, su, bp, *len);

    uint8_t rsvd, gm_prio_1, gm_prio_2, gm_clk_cls, gm_clk_acc, time_src;
    uint16_t origin_cur_utc, gm_clk_var, steps_removed;
    uint64_t gm_clock_id;
    uint64_t secs;
    uint32_t nsecs;

    /* sec time stamp 6 bytes */
    secs = GET_BE_U_6(bp);
    nd_filling_l2(ifn, su, 0, 6, LAYER_3_PTP_SECS, secs, p_origin_ts);

    *len -= 6;
    bp += 6;

    /* NS time stamp 4 bytes */
    nsecs = GET_BE_U_4(bp);
    nd_filling_l2(ifn, su, 0, 4, LAYER_3_PTP_NAOSECS, nsecs, p_origin_ts);

    *len -= 4;
    bp += 4;

    /* origin cur utc */
    origin_cur_utc = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_O_CUR_UTC, origin_cur_utc, p_origin_ts);
    
    *len -= 2;
    bp += 2;

    /* rsvd */
    rsvd = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_ORIGIN_RSVD, rsvd, p_origin_ts);
    
    *len -= 1;
    bp += 1;

    /* gm prio */
    gm_prio_1 = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_GM_PRIO_1, gm_prio_1, p_origin_ts);

    *len -= 1;
    bp += 1;

    /* GM clock class */
    gm_clk_cls = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_GM_CLOCK_CLASS, gm_clk_cls, p_origin_ts);

    *len -= 1;
    bp += 1;

    /* GM clock accuracy */
    gm_clk_acc = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_GM_CLOCK_ACCURACY, gm_clk_acc, p_origin_ts);

    *len -= 1;
    bp += 1;

    /* GM clock variance */
    gm_clk_var = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_GM_CLOCK_VARIANCE, gm_clk_var, p_origin_ts);

    *len -= 2;
    bp += 2;

    /* GM Prio 2 */
    gm_prio_2 = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_GM_PRIO_2, gm_prio_2, p_origin_ts);
    
    *len -= 1;
    bp += 1;

    /* GM Clock Identity */
    gm_clock_id = GET_BE_U_8(bp);
    nd_filling_l2(ifn, su, 0, 8, LAYER_3_PTP_GM_CLOCK_ID, gm_clock_id, p_origin_ts);
    
    *len -= 8;
    bp += 8;

    /* steps removed */
    steps_removed = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_STEPS_REMOVED, steps_removed, p_origin_ts);

    *len -= 2;
    bp += 2;

    /* Time source */
    time_src = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_PTP_TIME_SOURCE, time_src, p_origin_ts);
    
    *len -= 1;
    bp += 1;

    RVoid();
}

static void
ptp_print_port_id(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, const u_char *bp, u_int *len)
{

    TC("Called { %s(%p, %p, %p, %p, %u)", __func__, ndo, ifn, su, bp, *len);

    uint16_t port_id;
    uint64_t port_identity;

    /* port identity*/
    port_identity = GET_BE_U_8(bp);
    nd_filling_l2(ifn, su, 0, 8, LAYER_3_PTP_PORT_ID_STR, port_identity, "");
    
    *len -= 8;
    bp += 8;

    /* port id */
    port_id = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_PORTID, port_id, "");
    
    *len -= 2;
    bp += 2;

    RVoid();
}

static void
ptp_print_mgmt_msg(ndo_t *ndo, infonode_t *ifn, l1l2_node_t *su, const u_char *bp, u_int *len)
{
    TC("Called { %s(%p, %p, %p, %p, %u)", __func__, ndo, ifn, su, bp, *len);

    uint8_t u8_val;
    uint16_t port_id;
    uint64_t port_identity;

    /* port identity*/
    port_identity = GET_BE_U_8(bp);
    nd_filling_l2(ifn, su, 0, 8, LAYER_3_PTP_PORT_ID_STR, port_identity, " ");

    *len -= 8;
    bp += 8;

    /* port id */
    port_id = GET_BE_U_2(bp);
    nd_filling_l2(ifn, su, 0, 2, LAYER_3_PTP_PORTID, port_id, " ");

    *len -= 2;
    bp += 2;

    u8_val = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, "Start Boundary Hops: %u", u8_val);
    
    *len -= 1;
    bp += 1;

    u8_val = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, "Boundary Hops: %u", u8_val);

    *len -= 1;
    bp += 1;

    u8_val = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, "Flags: %x", u8_val);

    *len -= 1;
    bp += 1;

    u8_val = GET_U_1(bp);
    nd_filling_l2(ifn, su, 0, 1, "Reserved: %x", u8_val);

    *len -= 1;
    bp += 1;

    RVoid();
}