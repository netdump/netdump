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

#ifndef __ATODCOMM_H__
#define __ATODCOMM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"


/**
 * @brief
 *  ATOD memory start address
 */
#define ATODCOMM_SHM_BASEADDR       ((void *)(0x6EFE00000000))


/**
 * @brief
 *  Specify the size of the dataroom
 */
#define INFONODE_DATAROOM_SIZE      (73728UL)   // 72K


/**
 * @brief
 *  Specify the number of nodes
 */
#define INFONODE_NUMBER             (64UL)


/**
 * @brief
 *  This structure is a storage interface for all the information displayed.
 *  This structure is a linked list node.
 *  It has forward and backward members to build a linked list.
 * @memberof prev
 *  Point to the previous element
 * @memberof next
 *  Point to the next element
 * @memberof timestamp
 *  Storing timestamp strings
 * @memberof srcaddr
 *  Store source address string
 * @memberof dstaddr
 *  Stores the destination address string
 * @memberof protocol
 *  Storage protocol string
 * @memberof length
 *  Stores the length of a string
 * @memberof brief
 *  Stores brief information string
 * @memberof flag
 *  The protocol type of the corresponding layer of storage
 *  flag[2]
 *  flag[3]
 *  flag[4]
 * @memberof dataroom
 *  Space for storing detailed analysis of the protocol
 */
typedef struct infonode_s 
{

    void * prev;
    void * next;

    unsigned char timestamp[16];
    unsigned char srcaddr[48];
    unsigned char dstaddr[48];
    unsigned char protocol[16];
    unsigned char length[8];
    unsigned char brief[256];

    unsigned short flag[8];

    unsigned char dataroom[INFONODE_DATAROOM_SIZE];

} infonode_t;


/**
 * @brief
 *  Resources shared between the display process and the parsing process.
 * @memberof listhead
 *  This pointer always points to the head of the linked list.
 * @memberof listtail
 *  This pointer always points to the end of the linked list.
 * @memberof curline
 *  This pointer always points to the current specified row.
 * @memberof idlelist
 *  This pointer always points to the currently idle node element
 * @memberof nlines
 *  Indicates the number of rows that can be displayed in window 3
 * @memberof curindex
 *  Indicates the index of the currently specified display node in the linked list (starting from 0)
 * @memberof flag
 *  flag[0]: Indicates whether to manually intervene in the display
 *  flag[1]: Indicates whether it is a special message such as RST
 *  flag[2]: 1 means all nodes have been filled.
 *           0 means all content has been displayed and can be refilled
 *  flag[3]:
 */
typedef struct dtoainfo_s
{

    void * listhead;
    void * listtail;
    void * curline;
    void * idlelist;

    unsigned short nlines;
    unsigned short curindex;
    volatile unsigned char flag[4];

} dtoainfo_t;



#endif  // __ATODCOMM_H__