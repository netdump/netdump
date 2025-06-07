
#ifndef __INFONODE_H__
#define __INFONODE_H__

#include "common.h"


/**
 * @brief struct l1l2_node_s nums
 */
#define l1l2_NODE_NUMS                          (80U)
/**
 * @brief l1l2node content length
 */
#define L1L2NODE_CONTENT_LENGTH                 (128U)
/**
 * @brief level 1 and level 2 tittle node
 */
typedef struct l1l2_node_s l1l2_node_t;
struct l1l2_node_s 
{
    nd_dll_t l1l2node;
    nd_dll_t l1node;

    l1l2_node_t * superior;

    int level;
    int isexpand;
    
    #define INFONODE_BYTE_START_MAX             (65535U)
    int byte_start;                             // index from 0
    #define INFONODE_BYTE_END_MAX               (65535U)
    int byte_end;

    char content[L1L2NODE_CONTENT_LENGTH];
};


/**
 * @brief struct w5_node_s nums
 */
#define W5_NODE_NUMS                            (128U)
/**
 * @brief w5node content length                 
 */
#define W5NODE_CONTENT_LENGTH                   (96U)
/**
 * @brief window 5 content 
 */
typedef struct w5_node_s 
{
    nd_dll_t w5node;
    int startindex;
    int endindex;
    char content[W5NODE_CONTENT_LENGTH];
} w5_node_t;


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

    nd_dll_t * w5head;
    nd_dll_t * w5tail;

    unsigned short typel2;
    unsigned short typel3;
    unsigned short typel4;
    unsigned short typel5;

    unsigned long g_store_index;

    #define INFONODE_TIMESTAMP_LENGTH   (16U)
    char timestamp[INFONODE_TIMESTAMP_LENGTH];
    #define INFONODE_ADDR_LENGTH        (48U)
    char srcaddr[INFONODE_ADDR_LENGTH];
    char dstaddr[INFONODE_ADDR_LENGTH];
    #define INFONODE_PROTOCOL_LENGTH    (16U)
    char protocol[INFONODE_PROTOCOL_LENGTH];
    #define INFONODE_LENGTH_LENGTH      (8U)
    char length[INFONODE_LENGTH_LENGTH];
    #define INFONODE_BRIEF_LENGTH       (256U)
    char brief[INFONODE_BRIEF_LENGTH];

} infonode_t;



/**
 * @brief
 * 
 */
#define TYPE_L2_ETHER           (0x01)

#endif  // __INFONODE_H__
