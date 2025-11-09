
#include "ndo.h"
#include "header.h"
#include "a-f-extract.h"
#include "a-f-addrtoname.h"

#include "a-f-ip.h"
#include "a-f-udp.h"
#include "a-f-ipproto.h"

#include <sys/param.h>

/*
 * Interface Control Message Protocol Definitions.
 * Per RFC 792, September 1981.
 */

#if 0

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Rest of Header (Type-specific)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Data ...                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

#if 0
（Echo Request）
0       7 8      15 16     23 24     31
+--------+--------+--------+--------+
| Type=8 | Code=0 |      Checksum   |
+--------+--------+--------+--------+
|    Identifier   |  Sequence Num   |
+--------+--------+--------+--------+
|              Data...              |
+-----------------------------------+

#endif

#if 0

ICMP_UNREACH

0                   1                   2                   3  
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=3    |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Unused             |           Next-Hop MTU        | (*)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                     Original IP header + data                 ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif


#if 0

ICMP_REDIRECT

0                   1                   2                   3  
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=5    |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Gateway Internet Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Data Datagram       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif


#if 0

ICMP_ROUTERADVERT

0                   1                   2                   3  
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=9    |    Code=0     |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Num Addrs   |   Addr Entry Size  |          Lifetime        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Router Address[1]                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Preference Level[1]                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Router Address[2]                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Preference Level[2]                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |

#endif

#if 0
ICMP_TIMXCEED

0                   1                   2                   3  
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=11   |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Unused = 0 (32 bits)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Original IP Header + first 8 bytes of original data      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


RFC4884
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=11   |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Unused    |    Length     |           Unused              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + leading octets of original datagram    |
|      (Length × 4 bytes, padded to 32-bit boundary)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Extension Object(s)... (可选)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

#if 0

ICMP_PARAMPROB

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=12   |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Pointer    |                   Unused                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         Original IP Header                    +
|                                                               |
+            First 8 bytes of Original Datagram Data            +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


RFC 4884
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=12   |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Pointer    |    Length     |           Unused              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + leading octets of original datagram    |
|      (Length × 4 bytes, padded to 32-bit boundary)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Extension Object(s)... (可选)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

#if 0

ICMP_MASKREPLY

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=18   |     Code=0    |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Address Mask (32 bits)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

#if 0

ICMP_TSTAMP/ICMP_IREQREPLY

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Originate Timestamp                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Receive Timestamp                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Transmit Timestamp                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

#if 0

每个扩展报文在 ICMP 原始头之后开始，格式如下

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version |   Reserved  |          Checksum                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Length (octets)   |      Class-Num     |       C-Type      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Object Payload …                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

/*
 * Structure of an icmp header.
 */
struct icmp
{
    nd_uint8_t icmp_type;   /* type of message, see below */
    nd_uint8_t icmp_code;   /* type sub code */
    nd_uint16_t icmp_cksum; /* ones complement cksum of struct */
    union
    {
        nd_uint8_t ih_pptr; /* ICMP_PARAMPROB */
        nd_uint8_t unused_1byte;  /* RFC 4884 unused */
        nd_uint8_t length_rfc4884;  /* RFC 4884 length */
        nd_uint16_t unused_2byte; /* RFC 4884 unused */
        nd_ipv4 ih_gwaddr;  /* ICMP_REDIRECT */
        struct ih_idseq
        {
            nd_uint16_t icd_id;
            nd_uint16_t icd_seq;
        } ih_idseq;
        nd_uint32_t ih_void;
    } icmp_hun;
#define icmp_pptr icmp_hun.ih_pptr
#define icmp_rfc4884_1byte_unused icmp_hun.unused_1byte
#define icmp_rfc4884_length icmp_hun.length_rfc4884
#define icmp_rfc4884_2byte_unused icmp_hun.unused_2byte
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id icmp_hun.ih_idseq.icd_id
#define icmp_seq icmp_hun.ih_idseq.icd_seq
#define icmp_void icmp_hun.ih_void
    union
    {
        struct id_ts
        {
            nd_uint32_t its_otime;
            nd_uint32_t its_rtime;
            nd_uint32_t its_ttime;
        } id_ts;
        struct id_ip
        {
            struct ip idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        nd_uint32_t id_mask;
        nd_byte id_data[1];
    } icmp_dun;
#define icmp_otime icmp_dun.id_ts.its_otime
#define icmp_rtime icmp_dun.id_ts.its_rtime
#define icmp_ttime icmp_dun.id_ts.its_ttime
#define icmp_ip icmp_dun.id_ip.idi_ip
#define icmp_mask icmp_dun.id_mask
#define icmp_data icmp_dun.id_data
};

/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enough to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
#define	ICMP_MINLEN	8				/* abs minimum */
#define ICMP_EXTD_MINLEN (156 - sizeof (struct ip))     /* draft-bonica-internet-icmp-08 */
#define	ICMP_TSLEN	(8 + 3 * sizeof (uint32_t))	/* timestamp */
#define	ICMP_MASKLEN	12				/* address mask */
#define	ICMP_ADVLENMIN	(8 + sizeof (struct ip) + 8)	/* min */
#define	ICMP_ADVLEN(p)	(8 + (IP_HL(&(p)->icmp_ip) << 2) + 8)
	/* N.B.: must separately check that ip_hl >= 5 */

/*
 * Definition of type and code field values.
 */
#define	ICMP_ECHOREPLY		0		/* echo reply */
#define	ICMP_UNREACH		3		/* dest unreachable, codes: */
#define		ICMP_UNREACH_NET	0		/* bad net */
#define		ICMP_UNREACH_HOST	1		/* bad host */
#define		ICMP_UNREACH_PROTOCOL	2		/* bad protocol */
#define		ICMP_UNREACH_PORT	3		/* bad port */
#define		ICMP_UNREACH_NEEDFRAG	4		/* IP_DF caused drop */
#define		ICMP_UNREACH_SRCFAIL	5		/* src route failed */
#define		ICMP_UNREACH_NET_UNKNOWN 6		/* unknown net */
#define		ICMP_UNREACH_HOST_UNKNOWN 7		/* unknown host */
#define		ICMP_UNREACH_ISOLATED	8		/* src host isolated */
#define		ICMP_UNREACH_NET_PROHIB	9		/* prohibited access */
#define		ICMP_UNREACH_HOST_PROHIB 10		/* ditto */
#define		ICMP_UNREACH_TOSNET	11		/* bad tos for net */
#define		ICMP_UNREACH_TOSHOST	12		/* bad tos for host */
#define	ICMP_SOURCEQUENCH	4		/* packet lost, slow down */
#define	ICMP_REDIRECT		5		/* shorter route, codes: */
#define		ICMP_REDIRECT_NET	0		/* for network */
#define		ICMP_REDIRECT_HOST	1		/* for host */
#define		ICMP_REDIRECT_TOSNET	2		/* for tos and net */
#define		ICMP_REDIRECT_TOSHOST	3		/* for tos and host */
#define	ICMP_ECHO		8		/* echo service */
#define	ICMP_ROUTERADVERT	9		/* router advertisement */
#define	ICMP_ROUTERSOLICIT	10		/* router solicitation */
#define	ICMP_TIMXCEED		11		/* time exceeded, code: */
#define		ICMP_TIMXCEED_INTRANS	0		/* ttl==0 in transit */
#define		ICMP_TIMXCEED_REASS	1		/* ttl==0 in reass */
#define	ICMP_PARAMPROB		12		/* ip header bad */
#define		ICMP_PARAMPROB_OPTABSENT 1		/* req. opt. absent */
#define	ICMP_TSTAMP		13		/* timestamp request */
#define	ICMP_TSTAMPREPLY	14		/* timestamp reply */
#define	ICMP_IREQ		15		/* information request */
#define	ICMP_IREQREPLY		16		/* information reply */
#define	ICMP_MASKREQ		17		/* address mask request */
#define	ICMP_MASKREPLY		18		/* address mask reply */

#define	ICMP_MAXTYPE		18

#define ICMP_ERRTYPE(type) \
	((type) == ICMP_UNREACH || (type) == ICMP_SOURCEQUENCH || \
	(type) == ICMP_REDIRECT || (type) == ICMP_TIMXCEED || \
	(type) == ICMP_PARAMPROB)
#define	ICMP_MULTIPART_EXT_TYPE(type) \
	((type) == ICMP_UNREACH || \
         (type) == ICMP_TIMXCEED || \
         (type) == ICMP_PARAMPROB)
/* rfc1700 */
#ifndef ICMP_UNREACH_NET_UNKNOWN
#define ICMP_UNREACH_NET_UNKNOWN	6	/* destination net unknown */
#endif
#ifndef ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_UNREACH_HOST_UNKNOWN	7	/* destination host unknown */
#endif
#ifndef ICMP_UNREACH_ISOLATED
#define ICMP_UNREACH_ISOLATED		8	/* source host isolated */
#endif
#ifndef ICMP_UNREACH_NET_PROHIB
#define ICMP_UNREACH_NET_PROHIB		9	/* admin prohibited net */
#endif
#ifndef ICMP_UNREACH_HOST_PROHIB
#define ICMP_UNREACH_HOST_PROHIB	10	/* admin prohibited host */
#endif
#ifndef ICMP_UNREACH_TOSNET
#define ICMP_UNREACH_TOSNET		11	/* tos prohibited net */
#endif
#ifndef ICMP_UNREACH_TOSHOST
#define ICMP_UNREACH_TOSHOST		12	/* tos prohibited host */
#endif

/* rfc1716 */
#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB	13	/* admin prohibited filter */
#endif
#ifndef ICMP_UNREACH_HOST_PRECEDENCE
#define ICMP_UNREACH_HOST_PRECEDENCE	14	/* host precedence violation */
#endif
#ifndef ICMP_UNREACH_PRECEDENCE_CUTOFF
#define ICMP_UNREACH_PRECEDENCE_CUTOFF	15	/* precedence cutoff */
#endif

/* Most of the icmp types */
static const struct tok icmp2str[] = {
	{ ICMP_ECHOREPLY,		"echo reply" },
	{ ICMP_SOURCEQUENCH,		"source quench" },
	{ ICMP_ECHO,			"echo request" },
	{ ICMP_ROUTERSOLICIT,		"router solicitation" },
	{ ICMP_TSTAMP,			"time stamp request" },
	{ ICMP_TSTAMPREPLY,		"time stamp reply" },
	{ ICMP_IREQ,			"information request" },
	{ ICMP_IREQREPLY,		"information reply" },
	{ ICMP_MASKREQ,			"address mask request" },
	{ 0,				NULL }
};

/* rfc1191 */
struct mtu_discovery {
	nd_uint16_t unused;
	nd_uint16_t nexthopmtu;
};

/* rfc1256 */
struct ih_rdiscovery {
	nd_uint8_t ird_addrnum;
	nd_uint8_t ird_addrsiz;
	nd_uint16_t ird_lifetime;
};

struct id_rdiscovery {
	nd_uint32_t ird_addr;
	nd_uint32_t ird_pref;
};

/*
 * RFC 4884 - Extended ICMP to Support Multi-Part Messages
 *
 * This is a general extension mechanism, based on the mechanism
 * in draft-bonica-icmp-mpls-02 ICMP Extensions for MultiProtocol
 * Label Switching.
 *
 * The Destination Unreachable, Time Exceeded
 * and Parameter Problem messages are slightly changed as per
 * the above RFC. A new Length field gets added to give
 * the caller an idea about the length of the piggybacked
 * IP packet before the extension header starts.
 *
 * The Length field represents length of the padded "original datagram"
 * field  measured in 32-bit words.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     unused    |    Length     |          unused               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Internet Header + leading octets of original datagram    |
 * |                                                               |
 * |                           //                                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#if 0

每个扩展报文在 ICMP 原始头之后开始，格式如下

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version |   Reserved  |          Checksum                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Length (octets)   |      Class-Num     |       C-Type      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Object Payload …                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#endif

struct icmp_ext_t {
    nd_uint8_t  icmp_type;
    nd_uint8_t  icmp_code;
    nd_uint16_t icmp_checksum;
    nd_byte     icmp_reserved;
    nd_uint8_t  icmp_length;
    nd_byte     icmp_reserved2[2];
    nd_byte     icmp_ext_legacy_header[128]; /* extension header starts 128 bytes after ICMP header */
    nd_byte     icmp_ext_version_res[2];
    nd_uint16_t icmp_ext_checksum;
    nd_byte     icmp_ext_data[1];
};

/*
 * Extract version from the first octet of icmp_ext_version_res.
 */
#define ICMP_EXT_EXTRACT_VERSION(x) (((x)&0xf0)>>4)

/*
 * Current version.
 */
#define ICMP_EXT_VERSION 2

/*
 * Extension object class numbers.
 *
 * Class 1 dates back to draft-bonica-icmp-mpls-02.
 */

/* rfc4950  */
#define MPLS_STACK_ENTRY_OBJECT_CLASS            1

struct icmp_multipart_ext_object_header_t {
    nd_uint16_t length;
    nd_uint8_t  class_num;
    nd_uint8_t  ctype;
};

static const struct tok icmp_multipart_ext_obj_values[] = {
    { 1, "MPLS Stack Entry" },
    { 2, "Interface Identification" },
    { 0, NULL}
};


#define LAYER_4_ICMPV4_CONTENT                      "Internet Control Message Protocol V4:"
#define LAYER_4_ICMPV4_TYPE                         "type: %d (%s)"
#define LAYER_4_ICMPV4_CODE                         "code: %d"
#define LAYER_4_ICMPV4_CHECKSUM                     "checksum: 0x%04x"
#define LAYER_4_ICMPV4_ECHO_ID                      "identifier: 0x%04x"
#define LAYER_4_ICMPV4_ECHO_SEQ                     "sequence number: %d"
#define LAYER_4_ICMPV4_ECHO_DATA                    "data: "
#define LAYER_4_ICMPV4_UNREACH_UNUSED               "unused: 0x%08x"
#define LAYER_4_ICMPV4_UNREACH_NHMTU                "next-hop mtu: 0x%04x"
#define LAYER_4_ICMPV4_REDIRECT_GWADDR              "gateway internet address: %s"
#define LAYER_4_ICMPV4_ROUTERADVERT_NUMS            "number addrs: %d"
#define LAYER_4_ICMPV4_ROUTERADVERT_AES             "addr entry size: %d"
#define LAYER_4_ICMPV4_ROUTERADVERT_LIFETIME        "lifetime: %d"
#define LAYER_4_ICMPV4_ROUTERADVERT_ROUTER_ADDR     "router address[%d]: %s"
#define LAYER_4_ICMPV4_ROUTERADVERT_PL              "preference level[%d]: %u"
#define LAYER_4_ICMPV4_PARAMPROB_POINTER            "poiniter: %d"
#define LAYER_4_ICMPV4_MASK_REPLY                   "mask reply: 0x%08x"
#define LAYER_4_ICMPV4_O_TIMESTAMP                  "originate timestamp: %s"
#define LAYER_4_ICMPV4_R_TIMESTAMP                  "receive timestamp: %s"
#define LAYER_4_ICMPV4_T_TIMESTAMP                  "transmit timestamp: %s"

#define LAYER_4_ICMPV4_RFC4884_UNUSED_1BYTE         "rfc4884 unused: %02x"
#define LAYER_4_ICMPV4_RFC4884_LENGTH               "rfc4884 length: %d (%d)"
#define LAYER_4_ICMPV4_RFC4884_UNUSED_2BYTE         "rfc4884 unused: %04x"

#define LAYER_4_ICMPV4_ORIGINAL_DATAGRAM            "the original datagram has not been paresd yet:"


#define LAYER_4_ICMPV4_MUTIL_PART_EXTENSION         "icmp multi-part extension: v%u %s"
#define LAYER_4_ICMPV4_MUTIL_PART_RESERVED          "icmp multi-part reserved: %u"
#define LAYER_4_ICMPV4_MUTIL_PART_CHEKSUM           "icmp multi-part checksum: 0x%04x (%scorrect)"

#define LAYER_4_ICMPV4_MUTIL_PART_OBJ_LEN           "object length: %u"
#define LAYER_4_ICMPV4_MUTIL_PART_OBJ_CLASS_NUM     "object: %s (%u)"
#define LAYER_4_ICMPV4_MUTIL_PART_OBJ_CTYPE         "object class type: %u"
#define LAYER_4_ICMPV4_MUTIL_PART_OBJ_CONTENT       "object content (Currently not supported)"

/* prototypes */
const char *icmp_tstamp_print(u_int);

/* print the milliseconds since midnight UTC */
const char *
icmp_tstamp_print(u_int tstamp)
{
    u_int msec,sec,min,hrs;

    static char buf[64];

    msec = tstamp % 1000;
    sec = tstamp / 1000;
    min = sec / 60; sec -= min * 60;
    hrs = min / 60; min -= hrs * 60;
    snprintf(buf, sizeof(buf), "%02u:%02u:%02u.%03u",hrs,min,sec,msec);
    return buf;
}

void icmp_print(ndo_t *ndo, u_int *indexp, void *infonode, const u_char *bp, 
                u_int plen, const u_char *bp2, int fragmented)
{

    TC("Called { %s(%p, %p, %u, %p, %p, %u, %p, %d)", __func__, ndo, infonode, 
        *indexp, indexp, bp, plen, bp2, fragmented);

    char *cp;
    const struct icmp *dp;
    uint8_t icmp_type, icmp_code;
    const struct icmp_ext_t *ext_dp;
    const struct ip *ip;
    const char *str;
    const struct ip *oip;
    uint8_t ip_proto;
    const struct udphdr *ouh;
    const uint8_t *obj_tptr;
    //uint32_t raw_label;
    const struct icmp_multipart_ext_object_header_t *icmp_multipart_ext_object_header;
    u_int hlen, mtu, obj_tlen, obj_class_num, obj_ctype;
    uint16_t dport;
    char buf[MAXHOSTNAMELEN + 100];
    struct cksum_vec vec[1];

    ndo->ndo_protocol = "icmp";
    dp = (const struct icmp *)bp;
    ext_dp = (const struct icmp_ext_t *)bp;
    ip = (const struct ip *)bp2;
    str = buf;

    u_int idx = *indexp;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    su = nd_get_fill_put_l1l2_node_level1(ifn, 0, 0, 0, "%s", LAYER_4_ICMPV4_CONTENT);

    icmp_type = GET_U_1(dp->icmp_type);
    icmp_code = GET_U_1(dp->icmp_code);

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, LAYER_4_ICMPV4_TYPE, 
            icmp_type, tok2str(icmp2str, "type-#%u", icmp_type));
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, LAYER_4_ICMPV4_CODE, icmp_code);
    idx = idx + 1;

    if (ndo->ndo_vflag && !fragmented)
    { 
        /* don't attempt checksumming if this is a frag */
        if (ND_TTEST_LEN(bp, plen))
        {
            uint16_t sum;

            vec[0].ptr = (const uint8_t *)(const void *)dp;
            vec[0].len = plen;
            sum = in_cksum(vec, 1);

            if (sum != 0)
            {
                uint16_t icmp_sum = GET_BE_U_2(dp->icmp_cksum);
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                    LAYER_4_ICMPV4_CHECKSUM"(incorrect -> 0x%04x)", 
                    GET_BE_U_2(dp->icmp_cksum), in_cksum_shouldbe(icmp_sum, sum));
                idx = idx + 2;
            }
            else {
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                    LAYER_4_ICMPV4_CHECKSUM, GET_BE_U_2(dp->icmp_cksum));
                idx = idx + 2;
            }
        }
        else {
            idx = idx + 2;
        }
    }

    switch (icmp_type) {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            (void)snprintf(buf, sizeof(buf), "echo %s, id %u, seq %u",
                           icmp_type == ICMP_ECHO ? "request" : "reply",
                           GET_BE_U_2(dp->icmp_id),
                           GET_BE_U_2(dp->icmp_seq));
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                LAYER_4_ICMPV4_ECHO_ID, GET_BE_U_2(dp->icmp_id));
            idx = idx + 2;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                LAYER_4_ICMPV4_ECHO_SEQ, GET_BE_U_2(dp->icmp_seq));
            idx = idx + 2;
            TC("plen: %u, idx: %u, plen - 8: %u", plen, idx, (plen - 8));
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + plen - 8 - 1, 
                LAYER_4_ICMPV4_ECHO_DATA);
            idx = idx + plen - 8;
            break;
        case ICMP_UNREACH:
            switch (icmp_code) {
                case ICMP_UNREACH_NET:
                    (void)snprintf(buf, sizeof(buf),
                        "net %s unreachable",
                        GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_HOST:
                    (void)snprintf(buf, sizeof(buf),
                        "host %s unreachable",
                        GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    (void)snprintf(buf, sizeof(buf),
                        "%s protocol %u unreachable",
                        GET_IPADDR_STRING(dp->icmp_ip.ip_dst),
                        GET_U_1(dp->icmp_ip.ip_p));
                    break;
                case ICMP_UNREACH_PORT:
                    ND_TCHECK_1(dp->icmp_ip.ip_p);
                    oip = &dp->icmp_ip;
                    hlen = IP_HL(oip) * 4;
                    ouh = (const struct udphdr *)(((const u_char *)oip) + hlen);
                    dport = GET_BE_U_2(ouh->uh_dport);
                    ip_proto = GET_U_1(oip->ip_p);
                    switch (ip_proto) {
                        case IPPROTO_TCP:
                            (void)snprintf(buf, sizeof(buf),
                                "%s tcp port %u unreachable",
                                GET_IPADDR_STRING(oip->ip_dst), dport);
                            break;
                        case IPPROTO_UDP:
                            (void)snprintf(buf, sizeof(buf),
                                "%s udp port %u unreachable",
                                GET_IPADDR_STRING(oip->ip_dst), dport);
                            break;
                        default:
                            (void)snprintf(buf, sizeof(buf),
                                "%s protocol %u port %u unreachable",
                                GET_IPADDR_STRING(oip->ip_dst),
                                ip_proto, dport);
                            break;
                    }
                    break;
                case ICMP_UNREACH_NEEDFRAG:
                    {
                        const struct mtu_discovery *mp;
                        mp = (const struct mtu_discovery *)(const u_char *)&dp->icmp_void;
                        mtu = GET_BE_U_2(mp->nexthopmtu);
                        if (mtu) {
                            (void)snprintf(buf, sizeof(buf),
                                           "%s unreachable - need to frag (mtu %u)",
                                           GET_IPADDR_STRING(dp->icmp_ip.ip_dst), mtu);
                        }
                        else {
                            (void)snprintf(buf, sizeof(buf),
                                           "%s unreachable - need to frag",
                                           GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                        }
                    }
                    break;
                case ICMP_UNREACH_SRCFAIL:
                    (void)snprintf(buf, sizeof(buf),
                            "%s unreachable - source route failed",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_NET_UNKNOWN:
                    (void)snprintf(buf, sizeof(buf),
                            "net %s unreachable - unknown",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_HOST_UNKNOWN:
                    (void)snprintf(buf, sizeof(buf),
                            "host %s unreachable - unknown",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_ISOLATED:
                    (void)snprintf(buf, sizeof(buf),
                            "%s unreachable - source host isolated",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_NET_PROHIB:
                    (void)snprintf(buf, sizeof(buf),
                            "net %s unreachable - admin prohibited",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_HOST_PROHIB:
                    (void)snprintf(buf, sizeof(buf),
                            "host %s unreachable - admin prohibited",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_TOSNET:
                    (void)snprintf(buf, sizeof(buf),
                            "net %s unreachable - tos prohibited",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_TOSHOST:
                    (void)snprintf(buf, sizeof(buf),
                            "host %s unreachable - tos prohibited",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_FILTER_PROHIB:
                    (void)snprintf(buf, sizeof(buf),
                            "host %s unreachable - admin prohibited filter",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_HOST_PRECEDENCE:
                    (void)snprintf(buf, sizeof(buf),
                            "host %s unreachable - host precedence violation",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                case ICMP_UNREACH_PRECEDENCE_CUTOFF:
                    (void)snprintf(buf, sizeof(buf),
                            "host %s unreachable - precedence cutoff",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst));
                    break;
                default:
                    (void)snprintf(buf, sizeof(buf),
                            "%s unreachable - #%u",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst),
                            icmp_code);
                    break;
            }
            if (icmp_code == ICMP_UNREACH_NEEDFRAG)
            {
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                            LAYER_4_ICMPV4_UNREACH_UNUSED, GET_BE_U_2(dp->icmp_id));
                idx = idx + 2;
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                            LAYER_4_ICMPV4_UNREACH_NHMTU, GET_BE_U_2(dp->icmp_seq));
                idx = idx + 2;
            }
            else 
            {
                if (GET_U_1(dp->icmp_rfc4884_length))
                {
                    // RFC 4884
                    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                                LAYER_4_ICMPV4_RFC4884_UNUSED_1BYTE, GET_U_1(dp->icmp_rfc4884_1byte_unused));
                    idx = idx + 1;
                    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                                LAYER_4_ICMPV4_RFC4884_LENGTH, GET_U_1(dp->icmp_rfc4884_length),
                            (GET_U_1(dp->icmp_rfc4884_length) * 4));
                    idx = idx + 1;
                    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                                LAYER_4_ICMPV4_RFC4884_UNUSED_2BYTE, GET_BE_U_2(dp->icmp_rfc4884_2byte_unused));
                    idx = idx + 2;
                }
                else {
                    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                                LAYER_4_ICMPV4_UNREACH_UNUSED, GET_BE_U_4(dp->icmp_void));
                    idx = idx + 4;
                }
            }
            break;
        case ICMP_REDIRECT:
            switch (icmp_code) {
                case ICMP_REDIRECT_NET:
                    (void)snprintf(buf, sizeof(buf),
                            "redirect %s to net %s",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst),
                            GET_IPADDR_STRING(dp->icmp_gwaddr));
                    break;
                case ICMP_REDIRECT_HOST:
                    (void)snprintf(buf, sizeof(buf),
                            "redirect %s to host %s",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst),
                            GET_IPADDR_STRING(dp->icmp_gwaddr));
                    break;
                case ICMP_REDIRECT_TOSNET:
                    (void)snprintf(buf, sizeof(buf),
                            "redirect-tos %s to net %s",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst),
                            GET_IPADDR_STRING(dp->icmp_gwaddr));
                    break;
                case ICMP_REDIRECT_TOSHOST:
                    (void)snprintf(buf, sizeof(buf),
                            "redirect-tos %s to host %s",
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst),
                            GET_IPADDR_STRING(dp->icmp_gwaddr));
                    break;
                default:
                    (void)snprintf(buf, sizeof(buf),
                            "redirect-#%u %s to %s", icmp_code,
                            GET_IPADDR_STRING(dp->icmp_ip.ip_dst),
                            GET_IPADDR_STRING(dp->icmp_gwaddr));
                    break;
            }
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, 
                        LAYER_4_ICMPV4_REDIRECT_GWADDR, 
                        GET_IPADDR_STRING(dp->icmp_gwaddr));
            idx = idx + 4;
            break;
        case ICMP_ROUTERADVERT:
            {
                const struct ih_rdiscovery *ihp;
                const struct id_rdiscovery *idp;
                u_int lifetime, num, size;
                (void)snprintf(buf, sizeof(buf), "router advertisement");
                cp = buf + strlen(buf);
                ihp = (const struct ih_rdiscovery *)&dp->icmp_void;
                ND_TCHECK_SIZE(ihp);
                (void)strncpy(cp, " lifetime ", sizeof(buf) - (cp - buf));
                cp = buf + strlen(buf);
                lifetime = GET_BE_U_2(ihp->ird_lifetime);
                if (lifetime < 60) {
                    (void)snprintf(cp, sizeof(buf) - (cp - buf), "%u",
                        lifetime);
                } else if (lifetime < 60 * 60) {
                    (void)snprintf(cp, sizeof(buf) - (cp - buf), "%u:%02u",
                        lifetime / 60, lifetime % 60);
                } else {
                    (void)snprintf(cp, sizeof(buf) - (cp - buf),
                        "%u:%02u:%02u",
                        lifetime / 3600,
                        (lifetime % 3600) / 60,
                        lifetime % 60);
                }
                cp = buf + strlen(buf);
                num = GET_U_1(ihp->ird_addrnum);
                (void)snprintf(cp, sizeof(buf) - (cp - buf), " %u:", num);
                cp = buf + strlen(buf);
                size = GET_U_1(ihp->ird_addrsiz);
                if (size != 2) {
                    (void)snprintf(cp, sizeof(buf) - (cp - buf), " [size %u]", size);
                    break;
                }
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                    LAYER_4_ICMPV4_ROUTERADVERT_NUMS, num);
                idx = idx + 1;
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, 
                    LAYER_4_ICMPV4_ROUTERADVERT_AES, size);
                idx = idx + 1;
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, 
                    LAYER_4_ICMPV4_ROUTERADVERT_LIFETIME, lifetime);
                idx = idx + 2;
                idp = (const struct id_rdiscovery *)&dp->icmp_data;
                int i = 0;
                while (num > 0)
                {
                    ND_TCHECK_SIZE(idp);
                    (void)snprintf(cp, sizeof(buf) - (cp - buf), " {%s %u}",
                                   GET_IPADDR_STRING(idp->ird_addr),
                                   GET_BE_U_4(idp->ird_pref));
                    cp = buf + strlen(buf);
                    ++idp;
                    num--;
                    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                            LAYER_4_ICMPV4_ROUTERADVERT_ROUTER_ADDR, i, 
                        GET_IPADDR_STRING(idp->ird_addr));
                    idx = idx + 4;
                    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                            LAYER_4_ICMPV4_ROUTERADVERT_PL, i, 
                        GET_BE_U_4(idp->ird_pref));
                    idx = idx + 4;
                    i++;
                }
            }
            break;
        case ICMP_TIMXCEED:
            ND_TCHECK_4(dp->icmp_ip.ip_dst);
            switch (icmp_code) {
                case ICMP_TIMXCEED_INTRANS:
                    str = "time exceeded in-transit";
                    break;
                case ICMP_TIMXCEED_REASS:
                    str = "ip reassembly time exceeded";
                    break;
                default:
                    (void)snprintf(buf, sizeof(buf), "time exceeded-#%u", icmp_code);
                    break;
            }
            if (GET_U_1(dp->icmp_rfc4884_length)) {
                // RFC 4884
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                        LAYER_4_ICMPV4_RFC4884_UNUSED_1BYTE, GET_U_1(dp->icmp_rfc4884_1byte_unused));
                idx = idx + 1;
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                        LAYER_4_ICMPV4_RFC4884_LENGTH, GET_U_1(dp->icmp_rfc4884_length),
                        (GET_U_1(dp->icmp_rfc4884_length) * 4));
                idx = idx + 1;
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_RFC4884_UNUSED_2BYTE, GET_BE_U_2(dp->icmp_rfc4884_2byte_unused));
                idx = idx + 2;
            }
            else {
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_UNREACH_UNUSED, GET_BE_U_4(dp->icmp_void));
                idx = idx + 4;
            }
            break;
        case ICMP_PARAMPROB:
            if (icmp_code) {
                (void)snprintf(buf, sizeof(buf), "parameter problem - code %u", icmp_code);
            }
            else {
                (void)snprintf(buf, sizeof(buf), "parameter problem - octet %u", GET_U_1(dp->icmp_pptr));
            }
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                    LAYER_4_ICMPV4_PARAMPROB_POINTER, GET_U_1(dp->icmp_pptr));
            idx = idx + 1;
            if (GET_U_1(dp->icmp_rfc4884_length))
            {
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                        LAYER_4_ICMPV4_RFC4884_LENGTH, GET_U_1(dp->icmp_rfc4884_length),
                        (GET_U_1(dp->icmp_rfc4884_length) * 4));
                idx = idx + 1;
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_RFC4884_UNUSED_2BYTE, GET_BE_U_2(dp->icmp_rfc4884_2byte_unused));
                idx = idx + 2;
            }
            else 
            {
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 3 - 1,
                        "unused: %d", GET_BE_U_3((dp->icmp_pptr + 1)));
                idx = idx + 3;
            }
            break;
        case ICMP_MASKREPLY:
            (void)snprintf(buf, sizeof(buf), "address mask is 0x%08x",
                        GET_BE_U_4(dp->icmp_mask));
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_ECHO_ID, GET_BE_U_2(dp->icmp_id));
            idx = idx + 2;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_ECHO_SEQ, GET_BE_U_2(dp->icmp_seq));
            idx = idx + 2;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_MASK_REPLY, GET_BE_U_4(dp->icmp_mask));
            idx = idx + 4;
            break;
        case ICMP_TSTAMP:
            (void)snprintf(buf, sizeof(buf),
                        "time stamp query id %u seq %u",
                        GET_BE_U_2(dp->icmp_id),
                        GET_BE_U_2(dp->icmp_seq));
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_ECHO_ID, GET_BE_U_2(dp->icmp_id));
            idx = idx + 2;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_ECHO_SEQ, GET_BE_U_2(dp->icmp_seq));
            idx = idx + 2;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_O_TIMESTAMP, 
                        icmp_tstamp_print(GET_BE_U_4(dp->icmp_otime)));
            idx = idx + 4;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_R_TIMESTAMP, 
                        icmp_tstamp_print(GET_BE_U_4(dp->icmp_rtime)));
            idx = idx + 4;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_T_TIMESTAMP, 
                        icmp_tstamp_print(GET_BE_U_4(dp->icmp_ttime)));
            idx = idx + 4;
            
            break;
        case ICMP_TSTAMPREPLY:
            ND_TCHECK_4(dp->icmp_ttime);
            (void)snprintf(buf, sizeof(buf),
                           "time stamp reply id %u seq %u: org %s",
                           GET_BE_U_2(dp->icmp_id),
                           GET_BE_U_2(dp->icmp_seq),
                           icmp_tstamp_print(GET_BE_U_4(dp->icmp_otime)));
            (void)snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ", recv %s",
                           icmp_tstamp_print(GET_BE_U_4(dp->icmp_rtime)));
            (void)snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ", xmit %s",
                           icmp_tstamp_print(GET_BE_U_4(dp->icmp_ttime)));
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_ECHO_ID, GET_BE_U_2(dp->icmp_id));
            idx = idx + 2;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                        LAYER_4_ICMPV4_ECHO_SEQ, GET_BE_U_2(dp->icmp_seq));
            idx = idx + 2;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_O_TIMESTAMP, 
                        icmp_tstamp_print(GET_BE_U_4(dp->icmp_otime)));
            idx = idx + 4;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_R_TIMESTAMP, 
                        icmp_tstamp_print(GET_BE_U_4(dp->icmp_rtime)));
            idx = idx + 4;
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1,
                        LAYER_4_ICMPV4_T_TIMESTAMP, 
                        icmp_tstamp_print(GET_BE_U_4(dp->icmp_ttime)));
            idx = idx + 4;
            break;
        default:
            str = tok2str(icmp2str, "type-#%u", icmp_type);
            break;
    }

    if (ndo->ndo_vflag >= 1 && ICMP_ERRTYPE(icmp_type)) {
        const u_char *snapend_save;
        bp += 8;
        ip = (const struct ip *)bp;
        snapend_save = ndo->ndo_snapend;
        /*
         * Update the snapend because extensions (MPLS, ...) may be
         * present after the IP packet. In this case the current
         * (outer) packet's snapend is not what ip_print() needs to
         * decode an IP packet nested in the middle of an ICMP payload.
         *
         * This prevents that, in ip_print(), for the nested IP packet,
         * the remaining length < remaining caplen.
         */
        ndo->ndo_snapend = ND_MIN(bp + GET_BE_U_2(ip->ip_len),
                                  ndo->ndo_snapend);
        // need add function ip_print();

        if (ICMP_MULTIPART_EXT_TYPE(icmp_type))
        {
            if (GET_U_1(dp->icmp_rfc4884_length))
            {
                nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, 
                    idx + (GET_U_1(dp->icmp_rfc4884_length) * 4) - 1,
                        LAYER_4_ICMPV4_ORIGINAL_DATAGRAM);
                idx = idx + (GET_U_1(dp->icmp_rfc4884_length) * 4);
            }
        }
        else 
        {
            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, 
                    idx + plen - 8 - 1, LAYER_4_ICMPV4_ORIGINAL_DATAGRAM);
            idx = idx + plen - 8;
        }

        ndo->ndo_snapend = snapend_save;
    }

    /* ndo_protocol reassignment after ip_print() call */
    ndo->ndo_protocol = "icmp";
    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", plen - 8);
    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "%s", str);
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    /*
     * Attempt to decode multi-part message extensions (rfc4884) only for some ICMP types.
     */
    if (ndo->ndo_vflag >= 1 && plen > ICMP_EXTD_MINLEN && ICMP_MULTIPART_EXT_TYPE(icmp_type)) {
        ND_TCHECK_SIZE(ext_dp);
        /*
         * Check first if the multi-part extension header shows a non-zero length.
         * If the length field is not set then silently verify the checksum
         * to check if an extension header is present. This is expedient,
         * however not all implementations set the length field proper.
         */
        #if 0
        首先检查扩展头的 length 字段是否为非零。
        如果 length 字段是 0，那么“静默地”验证 checksum 来判断是否存在扩展头。
        这么做虽然有点投机取巧，但某些实现没有正确设置 length 字段。
        标准上 length 应该是非零的；
        但有些系统发的 ICMP 扩展包里，这个字段根本没填（为 0）；
        所以如果 length 为 0，我们就不能直接信任它；
        此时代码用 checksum 验证，来“猜测”这个包是否确实有扩展头。
        #endif
        if (GET_U_1(ext_dp->icmp_length) == 0 &&
            ND_TTEST_LEN(ext_dp->icmp_ext_version_res, plen - ICMP_EXTD_MINLEN))
        {
            vec[0].ptr = (const uint8_t *)(const void *)&ext_dp->icmp_ext_version_res;
            vec[0].len = plen - ICMP_EXTD_MINLEN;
            if (in_cksum(vec, 1))
            {
                RVoid();
            }
        }

        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                LAYER_4_ICMPV4_MUTIL_PART_EXTENSION,
                ICMP_EXT_EXTRACT_VERSION(*(ext_dp->icmp_ext_version_res)),
                (ICMP_EXT_EXTRACT_VERSION(*(ext_dp->icmp_ext_version_res)) != ICMP_EXT_VERSION) 
                ? "(packet not supported)" : ""
            );
        idx = idx + 1;

        /*
         * Sanity checking of the header.
         */
        if (ICMP_EXT_EXTRACT_VERSION(*(ext_dp->icmp_ext_version_res)) != ICMP_EXT_VERSION)
        {
            RVoid();
        }

        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                LAYER_4_ICMPV4_MUTIL_PART_RESERVED,
                ext_dp->icmp_ext_version_res[1]
            );
        idx = idx + 1;

        hlen = plen - ICMP_EXTD_MINLEN;
        if (ND_TTEST_LEN(ext_dp->icmp_ext_version_res, hlen))
        {
            vec[0].ptr = (const uint8_t *)(const void *)&ext_dp->icmp_ext_version_res;
            vec[0].len = hlen;

            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                LAYER_4_ICMPV4_MUTIL_PART_CHEKSUM,
                GET_BE_U_2(ext_dp->icmp_ext_checksum),
                in_cksum(vec, 1) ? "in" : ""
            );
            idx = idx + 2;
        }

        hlen -= 4; /* subtract common header size */
        obj_tptr = (const uint8_t *)ext_dp->icmp_ext_data;
        #if 0
        每个扩展报文在 ICMP 原始头之后开始，格式如下
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Version |   Reserved  |          Checksum                     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |    Length (octets)   |      Class-Num     |       C-Type      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Object Payload …                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #endif
        while (hlen > sizeof(struct icmp_multipart_ext_object_header_t)) {

            icmp_multipart_ext_object_header = (const struct icmp_multipart_ext_object_header_t *)obj_tptr;
            ND_TCHECK_SIZE(icmp_multipart_ext_object_header);
            obj_tlen = GET_BE_U_2(icmp_multipart_ext_object_header->length);
            obj_class_num = GET_U_1(icmp_multipart_ext_object_header->class_num);
            obj_ctype = GET_U_1(icmp_multipart_ext_object_header->ctype);
            obj_tptr += sizeof(struct icmp_multipart_ext_object_header_t);

            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1,
                LAYER_4_ICMPV4_MUTIL_PART_OBJ_LEN, obj_tlen
            );
            idx = idx + 2;

            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                LAYER_4_ICMPV4_MUTIL_PART_OBJ_CLASS_NUM, 
                tok2str(icmp_multipart_ext_obj_values,"unknown",obj_class_num),
                obj_class_num
            );
            idx = idx + 1;

            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx,
                LAYER_4_ICMPV4_MUTIL_PART_OBJ_CTYPE, obj_ctype
            );
            idx = idx + 1;
            /* length field includes tlv header */
            hlen -= sizeof(struct icmp_multipart_ext_object_header_t);

            /* infinite loop protection */
            if ((obj_class_num == 0) || (obj_tlen < sizeof(struct icmp_multipart_ext_object_header_t)))
            {
                RVoid();
            }
            obj_tlen -= sizeof(struct icmp_multipart_ext_object_header_t);

            nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + obj_tlen - 1,
                LAYER_4_ICMPV4_MUTIL_PART_OBJ_CONTENT
            );
            idx = idx + obj_tlen;

            if (hlen < obj_tlen)
                break;
            hlen -= obj_tlen;
            obj_tptr += obj_tlen;
        }
    }

    RVoid();

trunc:

    RVoid();
}