
#ifndef __INFONODE_H__
#define __INFONODE_H__

#include "common.h"

/**
 * @brief
 *  Specify the size of the dataroom
 */
#define INFONODE_DATAROOM_SIZE (73728UL) // 72K


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

#endif  // __INFONODE_H__
