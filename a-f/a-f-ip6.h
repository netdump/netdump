
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
Version	                4 bits	    协议版本号，IPv6为6
Traffic Class	        8 bits	    类似IPv4的TOS，用于QoS或优先级
Flow Label	            20 bits	    用于标识同一流的IP包（如VoIP）
Payload Length	        16 bits	    除去IPv6头部之外的负载长度
Next Header	            8 bits	    指示下一个协议头（如TCP/UDP/扩展头）
Hop Limit	            8 bits	    类似IPv4的TTL，每跳减一
Source Address	        128 bits	源 IPv6 地址
Destination Address	    128 bits	目标 IPv6 地址
#endif
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

#endif