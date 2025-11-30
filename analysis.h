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
#include <time.h>
#include <sys/time.h>

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
#include "c2a_comm.h"
#include "d2c_comm.h"
#include "a2d_comm.h"
#include "infonode.h"
#include "ndo.h"


/**
 * @brief
 *  Basic information display format
 */
#define BASIC_INFO_TOTAL_NUMS                       (5U)
#define BASIC_INFO_L1_TITLE                         (0U)
#define BASIC_INFO_L2_FRAME_NUMBER                  (1U)
#define BASIC_INFO_L2_ARRIVE_TIME                   (2U)
#define BASIC_INFO_L2_FRAME_LENGTH                  (3U)
#define BASIC_INFO_L2_CAPTURE_LENGTH                (4U)
#define BASIC_INFO_CONTENT                          "basic information"
#define BASIC_INFO_FORMAT                           "%s"
#define BASIC_INFO_SUB_SEQNUM                       "frame number: %lu"
#define BASIC_INFO_SUB_ARRIVE_TIME                  "arrive time: %s"
#define BASIC_INFO_SUB_FRAME_LENGTH                 "frame length: %u"
#define BASIC_INFO_SUB_CAPTURE_LENGTH               "capture length: %u"


#define ASCII_LINELENGTH                            (32U)
#define HEXDUMP_BYTES_PER_LINE                      (16U)
#define HEXDUMP_SHORTS_PER_LINE                     (HEXDUMP_BYTES_PER_LINE / (2U))
#define HEXDUMP_HEXSTUFF_PER_SHORT                  (5U) /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE                   (HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)


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
void analysis_network_frames(void *infonode, const struct pcap_pkthdr *h, const unsigned char *sp);


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


/**
 * @brief
 *  count the number of l1l2nodes
 */
void analysis_count_l1l2node_nums (nd_dll_t * idlehead);


/**
 * @brief
 *   count the number of w5nodes
 */
void analysis_count_w5node_nums (nd_dll_t *idlehead);


/**
 * @brief
 *  recover l1l2node
 * @param idlehead
 *  l1l2node idle list head
 * @param head
 *  head pointer to be recycled
 * @param tail
 *  tail pointer to be recycled
 * @param l1head
 *  l1head pointer to be recycled
 * @param l1tail
 *  l1tail pointer to be recycled
 */
void analysis_recover_l1l2node(
    nd_dll_t **idlehead, nd_dll_t **head, nd_dll_t **tail, nd_dll_t **l1head, nd_dll_t **l1tail);

/**
 * @brief
 *  recover w5node
 * @param idlehead
 *  w5node idle list head
 * @param head
 *  head pointer to be recycled
 * @param tail
 *  tail pointer to be recycled
 */
void analysis_recover_w5node(nd_dll_t **idlehead, nd_dll_t **head, nd_dll_t **tail);

#endif  // __ANALYSIS_H__