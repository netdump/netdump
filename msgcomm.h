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

#ifndef __MSGCOMM_H__
#define __MSGCOMM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "ring.h"


/**
 * @brief 
 *  Structure for message communication
 * @memberof comm
 *  Common structures for communication
 * @memberof msg.memery 
 *  The starting address of the memory space
 * @memberof msg.baseaddr
 *  Initialize the base address of the memory space
 * @memberof msg.dir
 *  Direction of message communication
 * @memberof msg.memspace 
 *  The size of the memory space for each element
 * @memberof msg.name 
 *  The file name corresponding to memory
 */
typedef struct {

	comm_t comm;
	
	struct {
		void * memory;
		void * baseaddr;
        unsigned int dir;
		unsigned int memspace;
		char name[COMM_NAMESIZE];
	} msg;
	
} msgcomm_t;


/**
 * @brief 
 *  The format used for message communication
 * @memberof dir
 *  Direction of message communication
 * @memberof msgtype
 *  Types of message communication
 * @memberof msg
 *  Message content
 */
typedef struct {
	
	unsigned int dir;
	unsigned int msgtype;
	unsigned int length;
	unsigned char msg[0];

} message_t;


/**
 * @brief 
 *  Communication direction display --> capture 0TO1
 */
#define MSGCOMM_DIR_0TO1        0x01U
/**
 * @brief 
 *  Communication direction capture --> display 1TO0
 */
#define MSGCOMM_DIR_1TO0        0x10U


/**
 * @brief
 *  Define the type of communication
 * @memberof MSGCOMM_SUC
 *  Message processed successfully
 * @memberof MSGCOMM_ACK
 *  Response after receiving the message
 * @memberof MSGCOMM_ERR
 *  Message processing error
 * @memberof MSGCOMM_CMD
 *  Command type message
 */
enum {
    MSGCOMM_SUC = 0XF0U,
    MSGCOMM_ACK = 0xF1U,
    MSGCOMM_ERR = 0XF2U,
    MSGCOMM_CMD = 0xF3U,
	MSGCOMM_FAD = 0xF4U,
	MSGCOMM_HLP = 0xF5U
};


/**
 * @brief 
 *  The base address used for message communication
 * @memberof MSGCOMM_BASE_ADDR_RING0TO1
 *  ring 0TO1 base address
 * @memberof MSGCOMM_BASE_ADDR__RING0TO1
 *  _ring 0TO1 base address
 * @memberof MSGCOMM_BASE_ADDR_MEM0TO1
 *  memery 0TO1 base address
 * @memberof MSGCOMM_BASE_ADDR_RING1TO0
 *  ring 1TO0 base address
 * @memberof MSGCOMM_BASE_ADDR__RING1TO0
 *  _ring 1TO0 base address
 * @memberof MSGCOMM_BASE_ADDR_MEM1TO0
 *  memery 1TO0 base address
 */
#define MSGCOMM_BASE_ADDR_RING0TO1              (void *)(0x6EE000000000)
#define MSGCOMM_BASE_ADDR__RING0TO1             (void *)(0x6EE001049000)
#define MSGCOMM_BASE_ADDR_MEM0TO1               (void *)(0x6EE002091000)
#define MSGCOMM_BASE_ADDR_RING1TO0              (void *)(0x6EE0030d9000)
#define MSGCOMM_BASE_ADDR__RING1TO0             (void *)(0x6EE004122000)
#define MSGCOMM_BASE_ADDR_MEM1TO0               (void *)(0x6EE00516a000)


/**
 * @brief 
 * 	Number of memory block elements and memory block size
 * @memberof MSGCOMM_BLOCK_NUMBERS
 * 	Number of memory block elements
 */
#define MSGCOMM_BLOCK_NUMBERS					64
#define MSGCOMM_MEMORY_SPACE					1024


/**
 * @brief 
 *  The file name used for message communication
 * @memberof MSGCOMM_RING_FNAME_0TO1
 *  ring 0TO1 file name
 * @memberof MSGCOMM__RING_FNAME_0TO1
 *  _ring 0TO1 file name
 * @memberof MSGCOMM_MEM_FNAME_0TO1
 *  memery 0TO1 file name
 * @memberof MSGCOMM_RING_FNAME_1TO0
 *  ring 1TO0 file name
 * @memberof MSGCOMM__RING_FNAME_1TO0
 *  _ring 1TO0 file name
 * @memberof MSGCOMM_MEM_FNAME_1TO0
 *  memory 1TO0 file name
 */
#define MSGCOMM_RING_FNAME_0TO1                 "/dev/shm/.Ring0TO1"
#define MSGCOMM__RING_FNAME_0TO1                "/dev/shm/._Ring0TO1"
#define MSGCOMM_MEM_FNAME_0TO1                  "/dev/shm/.Mem0TO1"
#define MSGCOMM_RING_FNAME_1TO0                 "/dev/shm/.Ring1TO0"
#define MSGCOMM__RING_FNAME_1TO0                "/dev/shm/._Ring1TO0"
#define MSGCOMM_MEM_FNAME_1TO0                  "/dev/shm/.Mem1TO0"


/**
 * @brief 
 *  Message communication resource initialization and startup
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_startup(void);


/**
 * @brief 
 *  Message communication resource destruction and exit
 */
void msgcomm_ending(void);


/**
 * @brief 
 *  Message communication module sends messages
 * @param dir
 *  Message direction
 * @param msgtype
 *  Message Type
 * @param msg
 *  Message content
 * @param length
 *  Message length
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_sendmsg(unsigned int dir, unsigned int msgtype, const char * msg, int length);


/**
 * @brief 
 *  Message communication module receives messages
 * @param 
 *  Message direction
 * @param message
 *  The message to be sent
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_recvmsg(unsigned int dir, message_t * message);


/**
 * @brief
 *  Check whether there is a message in the specified direction
 * @param dir
 *  Message direction
 * @return
 *  If it exists, it returns the number of messages.
 */
unsigned int msgcomm_detection(unsigned int dir);


/**
 * @brief
 *  Global variable msgcomm member information output
 */
void msgcomm_infodump(void);


/**
 * @brief 
 *  Calling this interface can complete a message transmission.
 * @param dir
 *  Message direction
 * @param msgtype
 *  Message Type
 * @param msg
 *  Message content
 * @param length
 *  Message length
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_message_send(unsigned int dir, unsigned int msgtype, const char * msg, int length);


/**
 * @brief 
 *  Calling this interface can complete a message reception.
 * @param 
 *  Message direction
 * @param message
 *  The message to be sent
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_message_recv (unsigned int dir, message_t * message);


/**
 * @brief 
 *  Child process lookup memory space
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR 
 */
int msgcomm_lookup (void);

#endif  // __MSGCOMM_H__