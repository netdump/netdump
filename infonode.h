
#ifndef __INFONODE_H__
#define __INFONODE_H__

#include "common.h"


/**
 * @brief
 *  struct l1l2_node_s nums
 */
#define l1l2_NODE_NUMS                          (80U)


/**
 * @brief l1l2node content length
 */
#define L1L2NODE_CONTENT_LENGTH                 (128U)


/**
 * @brief
 *  Specify the size of the dataroom
 */
#define INFONODE_DATAROOM_SIZE                  (8192U) // 8K


/**
 * @brief
 *  level 1 and level 2 tittle node
 */
typedef struct l1l2_node_s l1l2_node_t;
struct l1l2_node_s 
{
    nd_dll_t l1l2node;
    nd_dll_t l1node;

    l1l2_node_t * superior;

    int level;
    int isexpand;
    
    int byte_start;
    int byte_end;

    char content[L1L2NODE_CONTENT_LENGTH];
};


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

    nd_dll_t * l1l2head;
    nd_dll_t * l1l2tail;

    nd_dll_t * l1head;
    nd_dll_t * l1tail;

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

    unsigned int datalen;
    unsigned char dataroom[INFONODE_DATAROOM_SIZE];

} infonode_t;



/**
 * @brief
 * 
 */
#define TYPE_L2_ETHER           (0x01)

#endif  // __INFONODE_H__
