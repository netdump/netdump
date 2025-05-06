
#ifndef __INFONODE_H__
#define __INFONODE_H__

#include "common.h"

/**
 * @brief
 *  Specify the size of the dataroom
 */
#define INFONODE_DATAROOM_SIZE (66536UL) // 64K


/**
 * @brief
 *  The first entry in window 4 shows the basic information of the data frame
 */
typedef struct basic_info_s 
{
    #define BASIC_INFO_ARRIVAL_TIME_LENGTH      64
    char arrival_time[BASIC_INFO_ARRIVAL_TIME_LENGTH];
    unsigned long int frame_number;
    unsigned int frame_length;
    unsigned int capture_length;

} basic_info_t;


/**
 * @brief
 *  This structure is a storage interface for all the information displayed.
 *  This structure is a linked list node.
 *  It has forward and backward members to build a linked list.
 * @memberof listnode
 *  doubly linked list node
 * @memberof typel2
 *  second layer head type
 * @memberof typel3
 *  three-layer head type
 * @memberof typel4
 *  four-layer head type
 * @memberof typel5
 *  five-layer head type
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
 * @memberof dataroom
 *  Space for storing detailed analysis of the protocol
 */
typedef struct infonode_s
{

    nd_dll_t listnode;

    unsigned short typel2;
    unsigned short typel3;
    unsigned short typel4;
    unsigned short typel5;

    unsigned long g_store_index;

    char timestamp[16];
    char srcaddr[48];
    char dstaddr[48];
    char protocol[16];
    char length[8];
    char brief[256];

    basic_info_t basic_info;

    unsigned char dataroom[INFONODE_DATAROOM_SIZE];

} infonode_t;



/**
 * @brief
 * 
 */
#define TYPE_L2_ETHER           (0x01)

#endif  // __INFONODE_H__
