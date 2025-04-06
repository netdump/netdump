/**
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#ifndef __ANALYSIS_H__
#define __ANALYSIS_H__

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdint.h>
#include <stddef.h>
#include <poll.h>

#if 1
#include <net/ethernet.h> // 以太网帧
#include <netinet/ip.h>   // IPv4 头部
#include <netinet/ip6.h>  // IPv6 头部
#include <netinet/tcp.h>  // TCP 头部
#include <netinet/udp.h>  // UDP 头部
#include <arpa/inet.h>
#endif

#include "common.h"
#include "trace.h"
#include "sigact.h"
#include "ctoacomm.h"
#include "msgcomm.h"


/**
 * @brief 
 *  The main function of the packet parsing process
 * @param COREID
 *  COREID corresponding to the packet capture process
 * @param pname
 *  The name of the packet capture process
 * @param param
 *  Retain Parameters
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int analysis_main (unsigned int COREID, const char * pname, void * param);


/**
 * @brief 
 *  The main loop of the packet parsing process
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int analysis_loop (void);

#endif  // __ANALYSIS_H__