
#ifndef __AF_IP6_H__
#define __AF_IP6_H__

#include "ndo.h"

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

#if 0
Type 2 Routing header
0               1               2               3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   | Hdr Ext Len   | Routing Type  | Segments Left |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Reserved                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Home Address (128 bits)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

#if 0
Segment Routing Header 'SRH'
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header  | Hdr Ext Len | Routing Type | Segments Left     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Last Entry   |    Flags    |              Tag                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Segment List[0]                           |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Segment List[1]                           |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     ... 其他 Segment ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 可选 TLVs (Type-Length-Value)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif


#define LAYER_3_IP6_FORMAT                  "%s"
#define LAYER_3_IP6_CONTENT                 "Internet Protocol Version 6: "
#define LAYER_3_IP6_VERSION                 "version: %u"
#define LAYER_3_IP6_TC_FL                   "Traffic Class: 0x%02x, Flow Label: 0x%05x"
#define LAYER_3_IP6_PAYLOAD_LEN             "Payload Length: %u"
#define LAYER_3_IP6_NEXT_HEADER             "Next Header: %u (%s)"
#define LAYER_3_IP6_HOP_LIMIT               "Hop Limit: %u"
#define LAYER_3_IP6_SOURCE_ADDRESS          "Source Address: %s"
#define LAYER_3_IP6_DESTINATION_ADDRESS     "Destination Address: %s"
#define LAYER_3_IP6_HOP_BY_HOP_NXT_HEARDER  "Next Header: %u (%s) (Hop-By-Hop)"
#define LAYER_3_IP6_HOP_BY_HOP_LENGTH       "Hdr Ext Len: %u (Hop-By-Hop)"
#define LAYER_3_IP6_DEST_NXT_HEARDER        "Next Header: %u (%s) (Destination)"
#define LAYER_3_IP6_DEST_LENGTH             "Hdr Ext Len: %u (Destination)"

#define LAYER_3_IP6_FRAG6_NEXT_HEAD         "Next Header: %u (%s) (fragmentation)"
#define LAYER_3_IP6_FRAG6_RESERVED          "Reserved Field: %u (fragmentation)"
#define LAYER_3_IP6_FRAG6_OFFSET_FLAG       "Offset Flag: Offset: %u; Reserved: %u; Flag: %u (fragmentation)"
#define LAYER_3_IP6_FRAG6_IDENT             "Identification: 0x%08x (fragmentation)"

#define LAYER_3_IP6_RTHDR_NEXT_HEAD         "Next Header: %u (%s) (Routing header)"
#define LAYER_3_IP6_RTHDR_LENGTH            "Hdr Ext Len: %u (Routing header)"
#define LAYER_3_IP6_RTHDR_TYPE              "Routing Type: %u (Routing header)"
#define LAYER_3_IP6_RTHDR_SEGLEFT           "Segments Left: %u (Routing header)"
#define LAYER_3_IP6_RTHDR_RSV               "Reserved Field: 0x%0x (Routing header)"
#define LAYER_3_IP6_RTHDR_HOA               "Home Address: %s (Routing header)"

#define LAYER_3_IP6_RTHDR_SRH_LAST_ENTRY    "Last Entry: %u (Routing header)"
#define LAYER_3_IP6_RTHDR_SRH_FLAGS         "Flags: 0x%0x (Routing header)"
#define LAYER_3_IP6_RTHDR_SRH_TAG           "tag: %x (Routing header)"
#define LAYER_3_IP6_RTHDR_SRH_SID           "Segment List[%d] %s (Routing header)"

#define LAYER_3_IP6_MOBILITY_NEXT_HEADER    "Next Header: %u (%s) (Mobility)"
#define LAYER_3_IP6_MOBILITY_LENGTH         "Hdr Ext Len: %u (Mobility)"
#define LAYER_3_IP6_MOBILITY_MSG_TYPE       "Message Type: %u (%s) (Mobility)"
#define LAYER_3_IP6_MOBILITY_RESERVED       "Reserved: 0x%0x (Mobility)"
#define LAYER_3_IP6_MOBILITY_CHECKSUM       "Ckeck SUM: 0x%02x (Mobility)"
#define LAYER_3_IP6_MOBILITY_MESSAGE_DATA   "Message Data"

#define LAYER_3_IP6_OPT_PADN_VAL            "Option %s (%u) Value (%s)"
#define LAYER_3_IP6_OPT_ROUTER_ALERT        "Option ROUTER ALERT"

#define LAYER_3_IP6_OPT_TYPE                "Option %s (%u) (%s)"
#define LAYER_3_IP6_OPT_LENGTH              "Option %s (%u) Length %u (%s)"
#define LAYER_3_IP6_OPT_VALUE               "Option %s (%u) Value %u (%s)"
#define LAYER_3_IP6_OPT_VALUE_HEX           "Option %s (%u) Value 0x%x (%s)"
#define LAYER_3_IP6_OPT_JUMBO_VAL           "Option %s (%u) Value %u %s (%s)"
#define LAYER_3_IP6_OPT_HA_VAL_STR          "Option %s (%u) Value %s (%s)"
#define LAYER_3_IP6_OPT_OTHER_VAL           "Option %s (%u) Value (%s)"

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */

struct ip6_hdr
{
    union {
        struct ip6_hdrctl {
            nd_uint32_t ip6_un1_flow; /* 20 bits of flow-ID */
            nd_uint16_t ip6_un1_plen; /* payload length */
            nd_uint8_t ip6_un1_nxt;   /* next header */
            nd_uint8_t ip6_un1_hlim;  /* hop limit */
        } ip6_un1;
        nd_uint8_t ip6_un2_vfc; /* 4 bits version, top 4 bits class */
    } ip6_ctlun;
    nd_ipv6 ip6_src; /* source address */
    nd_ipv6 ip6_dst; /* destination address */
};

#define ip6_vfc                     ip6_ctlun.ip6_un2_vfc
#define IP6_VERSION(ip6_hdr)        ((GET_U_1((ip6_hdr)->ip6_vfc) & 0xf0) >> 4)
#define ip6_flow                    ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen                    ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt                     ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim                    ip6_ctlun.ip6_un1.ip6_un1_hlim

/*
 * Extension Headers
 */

struct ip6_ext
{
    nd_uint8_t ip6e_nxt;
    nd_uint8_t ip6e_len;
};

/* Hop-by-Hop options header */
struct ip6_hbh
{
    nd_uint8_t ip6h_nxt; /* next header */
    nd_uint8_t ip6h_len; /* length in units of 8 octets */
                         /* followed by options */
};

/* Destination options header */
struct ip6_dest
{
    nd_uint8_t ip6d_nxt; /* next header */
    nd_uint8_t ip6d_len; /* length in units of 8 octets */
                         /* followed by options */
};

/* Option types and related macros */
#define IP6OPT_PAD1                 0x00 /* 00 0 00000 */
#define IP6OPT_PADN                 0x01 /* 00 0 00001 */
#define IP6OPT_JUMBO		        0xC2 /* 11 0 00010 = 194 */
#define IP6OPT_JUMBO_LEN            6
#define IP6OPT_ROUTER_ALERT	        0x05 /* 00 0 00101 */

#define IP6OPT_RTALERT_LEN          4
#define IP6OPT_MINLEN		        2


#define IP6OPT_HOME_ADDRESS	        0xc9 /* 11 0 01001 */
#define IP6OPT_HOMEADDR_MINLEN      18


/* Routing header */
struct ip6_rthdr
{
    nd_uint8_t ip6r_nxt;     /* next header */
    nd_uint8_t ip6r_len;     /* length in units of 8 octets */
    nd_uint8_t ip6r_type;    /* routing type */
    nd_uint8_t ip6r_segleft; /* segments left */
                             /* followed by routing type specific data */
};

#define IPV6_RTHDR_TYPE_0 0
#define IPV6_RTHDR_TYPE_2 2
#define IPV6_RTHDR_TYPE_4 4

/* Type 0 Routing header */
/* Also used for Type 2 */
struct ip6_rthdr0
{
    nd_uint8_t ip6r0_nxt;       /* next header */
    nd_uint8_t ip6r0_len;       /* length in units of 8 octets */
    nd_uint8_t ip6r0_type;      /* always zero */
    nd_uint8_t ip6r0_segleft;   /* segments left */
    nd_uint32_t ip6r0_reserved; /* reserved field */
    nd_ipv6 ip6r0_addr[1];      /* up to 23 addresses */
};

/**
 * Type 4 Routing header
 * known as Segment Routing Header 'SRH'
 */
struct ip6_srh
{
    nd_uint8_t srh_nxt;      /* next header */
    nd_uint8_t srh_len;      /* length in units of 8 octets */
    nd_uint8_t srh_type;     /* Routing Type 4 */
    nd_uint8_t srh_segleft;  /* segments left */
    nd_uint8_t srh_last_ent; /* Last Entry*/
    nd_uint8_t srh_flags;    /* Flags */
    nd_uint16_t srh_tag;     /* Tag */
    nd_ipv6 srh_segments[1]; /* SRH segments list*/
};

/* Fragment header */
struct ip6_frag {
	nd_uint8_t  ip6f_nxt;               /* next header */
	nd_uint8_t  ip6f_reserved;          /* reserved field */
	nd_uint16_t ip6f_offlg;             /* offset, reserved, and flag */
	nd_uint32_t ip6f_ident;             /* identification */
};

#define IP6F_OFF_MASK		        0xfff8	/* mask out offset from ip6f_offlg */
#define IP6F_RESERVED_MASK	        0x0006	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		        0x0001	/* more-fragments flag */

#endif