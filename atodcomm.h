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

    nd_dll_t listnode;

    unsigned long g_store_index;

    char timestamp[16];
    char srcaddr[48];
    char dstaddr[48];
    char protocol[16];
    char length[8];
    char brief[256];

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
 * @memberof finlist
 *  Indicates a linked list that has been parsed but not displayed
 * @memberof nlines
 *  Indicates the number of rows that can be displayed in window 3
 * @memberof curindex
 *  Indicates the index of the currently specified display node in the linked list (starting from 0)
 * @memberof curlines
 *  Indicates the number of elements in the current linked list
 * @memberof finlines
 *  Indicates the number of nodes that have been parsed but not displayed
 * @memberof flag
 *  flag[0]: Indicates whether to manually intervene in the display
 *  flag[1]: Indicates whether it is a special message such as RST
 *  flag[2]: Display-related flags
 *  flag[3]: Flags related to parsing
 */
typedef struct dtoainfo_s
{

    nd_dll_t * listhead;
    nd_dll_t * listtail;
    nd_dll_t * curline;
    nd_dll_t * idlelist;
    nd_dll_t * finlisthead;
    nd_dll_t * finlisttail;

    unsigned short nlines;
    unsigned short curindex;
    unsigned short curlines;
    unsigned short finlines;
    volatile unsigned char flag[8];

} dtoainfo_t;

     
/**
 * @brief
 *  ATOD_DISPLAYING: Representatives are demonstrating the interface
 *  ATOD_DISPLAYED: The representative interface display has been completed
 */
#define DTOA_DISPLAY_VAR_FLAG       (G_dtoainfo->flag[2])    
#define DTOA_DISPLAYING             0x00
#define DTOA_DISPLAYED              0x01


/**
 * @brief
 *  DTOA_ANALYSISING: Indicates that data is being parsed
 *  DTOA_ALALYSISED: Indicates that data parsing has been completed
 */
#define ATOD_ANALYSIS_VAR_FLAG      (G_dtoainfo->flag[3])
#define ATOD_ANALYSISING            0x00
#define ATOD_ALALYSISED             0x01


/**
 * @brief
 *  DTOA_NON_MANUAL: Non-manual (ie automatic), the software automatically downloads
 *  DTOA_MANUAL_TOP: Manual mode and display the previous line of the current first line
 *  DTOA_MAMUAL_BOTTOM: Manual mode and display the next line of the current last line
 */
#define DTOA_ISOR_MANUAL_VAR_FLAG   (G_dtoainfo->flag[0])
#define DTOA_NON_MANUAL             0x00
#define DTOA_MANUAL_TOP             0x01
#define DTOA_MANUAL_BOTTOM          0x02


/**
 * @brief
 *  ATOD_DISPLAY_DLL_NUMS: current display DLL nums
 *  ATOD_FINISH_DLL_NUMS: finish DLL nums
 *  ATOD_DISPLAY_MAX_LINES: Maximum number of rows that can be displayed
 *  ATOD_CUR_DISPLAY_INDEX: current line index
 */
#define ATOD_DISPLAY_DLL_NUMS       (G_dtoainfo->curlines)
#define ATOD_FINISH_DLL_NUMS        (G_dtoainfo->finlines)
#define ATOD_DISPLAY_MAX_LINES      (G_dtoainfo->nlines)
#define ATOD_CUR_DISPLAY_LINE       (G_dtoainfo->curline)
#define ATOD_CUR_DISPLAY_INDEX      (G_dtoainfo->curindex)
#define ATOD_FINISH_DLL_HEAD        (G_dtoainfo->finlisthead)
#define ATOD_FINISH_DLL_TAIL        (G_dtoainfo->finlisttail)
#define ATOD_DISPLAY_DLL_HEAD       (G_dtoainfo->listhead)
#define ATOD_DISPLAY_DLL_TAIL       (G_dtoainfo->listtail)
#define ATOD_IDLE_DLL               (G_dtoainfo->idlelist)


/**
 * @brief
 *  Defines the maximum value of the nodes that can be placed in the display DLL each time
 */
#define ATOD_PUTIN_DISPLAY_DLL_MAX_NUMS     (6)


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
 *  Initialize G_dtoainfo to zero value
 */
void atodcomm_init_dtoainfo_to_zero(void);


/**
 * @brief
 *  Initialize the information node list
 */
int atodcomm_init_infonode_list (void);


/**
 * @brief
 *  Inter-process communication resource destruction operation
 */
void atodcomm_ending(void);

#endif  // __ATODCOMM_H_