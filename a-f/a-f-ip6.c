
#include "header.h"
#include "a-f-extract.h"
#include "a-f-ethertype.h"
#include "a-f-addrtoname.h"

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
 * print an IP6 datagram.
 */
void ip6_print(ndo_t *ndo, u_int index, void *infonode,
               const u_char *bp, u_int length)
{

    TC("Called { %s(%p, %p, %u, %p, %u)", __func__, ndo, infonode, index, bp, length);

    const struct ip6_hdr *ip6;

    ndo->ndo_protocol = "ip6";
    ip6 = (const struct ip6_hdr *)bp;

    RVoid();
}
