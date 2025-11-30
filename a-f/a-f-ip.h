
#ifndef __AF_IP_H__
#define __AF_IP_H__

#include "ndo.h"

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

#define LAYER_3_IP_FORMAT               "%s"
#define LAYER_3_IP_CONTENT              "Internet Protocol Version 4: "
#define LAYER_3_IP_VERSION              "version: %u"
#define LAYER_3_IP_HDRLEN               "header length: %u"
#define LAYER_3_IP_TOS                  "type of service: %02x, (dscp: %s, ecn: %s)"
#define LAYER_3_IP_TOTAL_LENGTH         "total length: %u"
#define LAYER_3_IP_TOTAL_LENGTH_TSO     "total length: %u [was 0, presumed TSO]"
#define LAYER_3_IP_IDENTIFICATION       "Identification: %u"
#define LAYER_3_IP_FLAGS                "flags: %02x (%s)"
#define LAYER_3_IP_FRAGMENT_OFFSET      "fragment offset: %u"
#define LAYER_3_IP_TIME_TO_LIVE         "time to live: %u"
#define LAYER_3_IP_PROTOCOL             "protocol: %u (%s)"
#define LAYER_3_IP_HEADER_CHECKSUM      "header checksum: %04x"
#define LAYER_3_IP_BAD_HEADER_CHECKSUM  "bad header checksum: %04x (-> %04x)"
#define LAYER_3_IP_SOURCE_ADDRESS       "source address: %s"
#define LAYER_3_IP_DESTINATION_ADDRESS  "destination address: %s"
#define LAYER_3_IP_OPTION_TYPE          "option type: %s (%02x)"
#define LAYER_3_IP_OPTION_LENGTH        "option length: %u"
#define LAYER_3_IP_OPTION_LENGTH_ERR    "option length: %u (bad length %u %s %u)"
#define LAYER_3_IP_OPTION_LENGTH_ERR1   "option length: %u (bad length %u %s %u != 0)"
#define LAYER_3_IP_OPTION_POINTER       "option pointer: %u"
#define LAYER_3_IP_OPTION_POINTER_ERR   "option pointer: %u (bad pointer)"
#define LAYER_3_IP_OPTION_OFLWFL        "option oflwfl: overflow: %u (hops not recorded); flag: %u (%s)"
#define LAYER_3_IP_OPTION_ADDR          "option address: %s"
#define LAYER_3_IP_OPTION_TS            "option timestamp: %u"
#define LAYER_3_IP_OPTION_VALUE_STR     "option value: %s"
#define LAYER_3_IP_OPTION_VALUE_04HEX   "option value: %04x"

/*
 * Structure of an internet header, naked of options.
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct ip {
    nd_uint8_t ip_vhl;              /* header length, version */
#define IP_V(ip)        ((GET_U_1((ip)->ip_vhl) & 0xf0) >> 4)
#define IP_HL(ip)       (GET_U_1((ip)->ip_vhl) & 0x0f)
    nd_uint8_t  ip_tos;             /* type of service */
    nd_uint16_t ip_len;             /* total length */
    nd_uint16_t ip_id;              /* identification */
    nd_uint16_t ip_off;             /* fragment offset field */
#define IP_DF   0x4000              /* don't fragment flag */
#define IP_MF   0x2000              /* more fragments flag */
#define IP_OFFMASK  0x1FFF          /* mask for fragmenting bits */
    nd_uint8_t  ip_ttl;             /* time to live */
    nd_uint8_t  ip_p;               /* protocol */
    nd_uint16_t ip_sum;             /* checksum */
    nd_ipv4     ip_src, ip_dst;     /* source and dest address */
};


#define	IPOPT_EOL		        0		/* end of option list */
#define	IPOPT_NOP		        1		/* no operation */

#define	IPOPT_RR		        7		/* record packet route */
#define	IPOPT_TS		        68		/* timestamp */
#define	IPOPT_RFC1393           82      /* traceroute RFC 1393 */
#define	IPOPT_SECURITY		    130		/* provide s,c,h,tcc */
#define	IPOPT_LSRR		        131		/* loose source route */
#define	IPOPT_SSRR		        137		/* strict source route */
#define IPOPT_RA                148     /* router-alert, rfc2113 */

/* flag bits for ipt_flg */
#define IPOPT_TS_TSONLY 0    /* timestamps only */
#define IPOPT_TS_TSANDADDR 1 /* timestamps and addresses */
#define IPOPT_TS_PRESPEC 3   /* specified modules only */

extern uint16_t nextproto4_cksum(ndo_t *, const struct ip *, const uint8_t *,
                                 u_int, u_int, uint8_t);

#endif