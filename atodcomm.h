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
 * @brief atod shared memory file name
 */
#define ATODCOMM_SHM_FILENAME       ".atodcomm.mem"


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
 * @memberof curlines
 *  Indicates the number of elements in the current linked list
 * @memberof flag
 *  flag[0]: Indicates whether to manually intervene in the display
 *  flag[1]: Indicates whether it is a special message such as RST
 *  flag[2]: Display-related flags
 *  flag[3]: Flags related to parsing
 */
typedef struct dtoainfo_s
{

    infonode_t * listhead;
    infonode_t * listtail;
    infonode_t * curline;
    infonode_t * idlelist;

    unsigned short nlines;
    unsigned short curindex;
    unsigned short curlines;
    unsigned short padding;
    volatile unsigned char flag[8];

} dtoainfo_t;


/**
 * @brief
 *  ATOD_DISPLAYING: Representatives are demonstrating the interface
 *  ATOD_DISPLAYED: The representative interface display has been completed
 */
#define ATOD_DISPLAYING         0x00
#define ATOD_DISPLAYED          0x01


/**
 * @brief
 *  DTOA_ANALYSISING: Indicates that data is being parsed
 *  DTOA_ALALYSISED: Indicates that data parsing has been completed
 */
#define DTOA_ANALYSISING        0x00
#define DTOA_ALALYSISED         0x01


/**
 * @brief
 *  DTOA_NON_MANUAL: Non-manual (ie automatic), the software automatically downloads
 *  DTOA_MANUAL_TOP: 
 */
#define DTOA_NON_MANUAL         0x00
#define DTOA_MANUAL_TOP         0x01
#define DTOA_MANUAL_BOTTOM      0x02


/**
 * @brief
 *  Global atod shared memory pointer variable
 */
extern void * G_atod_shm_mem;


/**
 * @brief
 *  DTOA global information interaction pointer
 */
extern dtoainfo_t * G_dtoainfo;


/**
 * @brief ctoa shared memory file size
 */
#define ATODCOMM_SHM_FILESIZE ((sizeof(infonode_t) + sizeof(dtoainfo_t)) * (INFONODE_NUMBER))


/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int atodcomm_startup(void);


/**
 * @brief
 *  Inter-process communication resource destruction operation
 */
void atodcomm_ending(void);


/**
 * @brief
 *  Remove a node from a doubly linked list
 * @memberof head
 *  Head of a doubly linked list
 * @return
 *  Returns a node if successful
 *  Returns NULL if failed
 */
infonode_t * atodcomm_takeout_infonode_from_list (infonode_t * head);


/**
 * @brief
 *  Return the node to the linked list
 * @memberof head
 *  Head of a doubly linked list
 * @memberof node
 *  Nodes to be returned
 * @return
 *  If successful, it returns ND_OK.
 *  If failed, it returns ND_ERR.
 */
int atodcomm_putin_infonode_to_list (infonode_t *head, infonode_t *node);


/**
 * @brief
 *  Take a node from the display list head
 * @memberof head
 *  Display link header
 * @return
 *  Returns a node if successful
 *  Returns NULL if failed
 */
infonode_t * atodcomm_takeout_infonode_from_display_list_head (infonode_t * head);


/**
 * @brief
 *  Take a node from the display list tail
 * @memberof tail
 *  Display the end of the linked list
 * @return
 *  Returns a node if successful
 *  Returns NULL if failed
 */
infonode_t * atodcomm_takeout_infonode_from_display_list_tail (infonode_t * tail);


/**
 * @brief
 *  Insert the node to the end of the display list
 * @memberof tail
 *  Display the end of the linked list
 * @memberof node
 *  Nodes to be returned
 * @return
 *  If successful, it returns ND_OK.
 *  If failed, it returns ND_ERR.
 */
int atod_putin_infonode_to_display_list_tail (infonode_t * tail, infonode_t * node);


/**
 * @brief
 *  Insert the node into the head of the display list
 * @memberof head
 *  Display link header
 * @memberof node
 *  Nodes to be returned
 * @return
 *  If successful, it returns ND_OK.
 *  If failed, it returns ND_ERR.
 */
int atod_putin_infonode_to_display_list_head (infonode_t * head, infonode_t * node);

#endif  // __ATODCOMM_H__