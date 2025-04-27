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
#include "atodcomm.h"


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


/**
 * @brief
 *  no manul mode analysis network frame
 */
void analysis_no_manual_mode (void);


/**
 * @brief
 *  manul mode analysis network frame
 */
void analysis_manual_mode(void);


/**
 * @brief
 *  Parsing network frames
 * @memberof header
 *  struct pcap_pkthdr pointer
 * @memberof packet
 *  network frame data
 */
void analysis_network_frames(const struct pcap_pkthdr *header, const unsigned char *packet);


/**
 * @brief
 *  Get infonode node pointer
 * @return
 *  Returns the obtained node pointer if successful.
 *  Returns NULL if failed
 */
infonode_t *analysis_get_infonode(void);


/**
 * @brief
 *  Put in infonode to finlist
 * @memberof infonode
 *  Waiting for the node element to be put into finlist
 */
void analysis_putin_infonode (infonode_t *infonode);


/**
 * @brief
 *  Take out the parsed DLL and put it into the display DLL;
 *  if the display DLL is full,
 *  take out some elements from the DLL header,
 *  put them into the free DLL,
 *  and then take out the parsed DLL and put it into the display DLL;
 *  if the display DLL is not full,
 *  take out the parsed DLL and put it into the display DLL
 *
 *  Update to show the number of elements in the DLL
 *  Specifies that the element currently displayed is not the last element of the DLL
 * @return
 *  Returns the number of entries added to the display DLL
 */
int analysis_put_node_into_display_dll(void);


#endif  // __ANALYSIS_H__