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
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

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
		//void * baseaddr;
        unsigned int dir;
		unsigned int memspace;
		//char name[COMM_NAMESIZE];
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
    MSGCOMM_SUC = 0xF0U,
    MSGCOMM_ACK = 0xF1U,
    MSGCOMM_ERR = 0XF2U,
    MSGCOMM_CMD = 0xF3U,
	MSGCOMM_FAD = 0xF4U,
	MSGCOMM_HLP = 0xF5U,
	MSGCOMM_DLT = 0xF6U
};

/**
 * @brief
 * 	Message Type Boundaries
 */
#define MSGCOMM_LEFT_VAL		0xF0U
#define MSGCOMM_RIGHT_VAL		0xF7U



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
#define MSGCOMM_BLOCK_NUMBERS					(1 << 4)
#define MSGCOMM_MEMORY_SPACE					(1 << 12)


/**
 * @brief
 * 	Redefine the name of the shared memory file
 */
#define MSGCOMM_MEMORY_NAME						".msgcomm.mem"


/**
 * @brief
 * 	Redefine the base address of shared memory
 */
#define MSGCOMM_MEMORY_BASE						(void *)(0x6EE000000000)

/**
 * @brief
 * 	Define some structures pointing to shared memory
 * @memberof faddr
 * 	Memory mapped address
 * @memberof buffer
 * 	DP store user input
 * @memberof reply
 * 	show CP reply DP message
 * @memberof space
 * 	Mainly used in the capture process to send messages to the display process
 * @memberof cmdmem
 * 	Mainly used in the capture process to receive messages from the display process
 * @memberof cpinfo
 * 	Used to display capture process information in the second TUI interface in the display process
 * @memberof memflag
 * 	Used for communication between the display process and the analysis process
 * @memberof reserve
 * 	reserve
 * @memberof argv
 * 	Pointer array to store the parsed command string
 * @memberof pktptrarr
 *	Pointer array to store the addresses of captured data packets
 * @note
 * 	buffer			4K(display use)
 * 	space			4K(capture use)
 *	cmdmem			4K(capture use)
 *	argv			4K
 *	cpinfo			4K(display second tui)
 *	flag			4k(display second tui and capture)
 *	reserve			32K
 *	pktsarray		1024 * 1024 * 16
 */
typedef struct {

	void * faddr;
	void * buffer;
	void * reply;
	void * space;
	void * cmdmem;
	void * cpinfo;
	void * memflag;
	void * reserve;
	void ** argv;
	void ** pktptrarr;

} memcomm_t;


/**
 * @brief
 *  Global variables, used in DP/CP/AA processes
 */
extern memcomm_t memcomm;


/**
 * @brief
 * 	Memory mapped address	
 */
#define msgcomm_G_faddr					(memcomm.faddr)

/**
 * @brief
 * 	DP store user input
 */
#define msgcomm_G_buffer				(memcomm.buffer)

/**
 * @brief
 * 	DP store user input
 */
#define msgcomm_G_reply					(memcomm.reply)

/**
 * @brief
 * 	Mainly used in the capture process to send messages to the display process
 */
#define msgcomm_G_sapce					(memcomm.space)

/**
 * @brief
 * 	Mainly used in the capture process to receive messages from the display process
 */
#define msgcomm_G_cmdmem				(memcomm.cmdmem)

/**
 * @brief
 * 	Used to display capture process information in the second TUI interface in the display process
 */
#define msgcomm_G_cpinfo				(memcomm.cpinfo)

/**
 * @brief
 * 	Used for communication between the display process and the analysis process
 */
#define msgcomm_G_memflag				(memcomm.memflag)

/**
 * @brief
 * 	reserve
 */
#define msgcomm_G_reserve				(memcomm.reserve)

/**
 * @brief
 * 	Pointer array to store the parsed command string
 */
#define msgcomm_G_argv					(memcomm.argv)

/**
 * @brief
 * 	Pointer array to store the addresses of captured data packets
 */
#define msgcomm_G_cpktptrarr			(memcomm.pktptrarr)

/**
 * @brief
 * 	memcomm.buffer size
 */
#define MSGCOMM_BUFFER_SIZE						(1 << 12)	// 4096

/**
 * @brief
 * 	memcomm.reply size
 */
#define MSGCOMM_REPLY_SIZE						(1 << 12)	// 4096

/**
 * @brief
 * 	memcomm_t.space size
 */
#define MSGCOMM_SPACE_SIZE 						(1 << 12)	// 4096

/**
 * @brief
 * 	memcomm_t.cmdmem size
 */
#define MSGCOMM_CMDMEM_SIZE 					(1 << 12)	// 4096

/**
 * @brief
 * 	memcomm_t.cpinfo size
 */
#define MSGCOMM_CPINFO_SIZE 					(1 << 12)	// 4096

/**
 * @brief
 * 	memcomm_t.memflag size
 */
#define MSGCOMM_MEMFLAG_SIZE 					(1 << 12)	// 4096

/**
 * @brief
 * 	memcomm_t.reserve size
 */
#define MSGCOMM_RESERVE_SIZE 					(1 << 15) 	// 32K

/**
 * @brief
 * 	memcomm_t.argv size
 */
#define MSGCOMM_ARGV_SIZE 						(1 << 12) 	// 4096

/**
 * @brief
 * 	memcomm_t.pktptrarr size
 */
#define MSGCOMM_PKTPTRARR_SIZE 					(1 << 24) 	// 16M


/**
 * @brief
 * 	Memory length after rounding 4096
 */
#define MSGCOMM_RING_T_SIZE						(((((sizeof(ring_t)) + (MSGCOMM_BLOCK_NUMBERS << 3)) >> 12) + 1) << 12)


/**
 * @brief
 * 	The actual memory size for storing data
 */
#define MSGCOMM_ACTUAL_SIZE						(MSGCOMM_MEMORY_SPACE * MSGCOMM_BLOCK_NUMBERS)


/**
 * @brief
 * 	Unified memory application for communication,
 * @note
 * 	_ring * 2 		[sizeof(struct ring) * 2 + MSGCOMM_BLOCK_NUMBERS * 8]
 * 	ring * 2		[sizeof(struct ring) * 2 + MSGCOMM_BLOCK_NUMBERS * 8]
 * 	memory * 2		[MSGCOMM_MEMORY_SPACE * MSGCOMM_BLOCK_NUMBERS * 2]
 */
#define MSGCOMM_MSGCOMM_MEMORY_SIZE				(((MSGCOMM_RING_T_SIZE) << 2) + ((MSGCOMM_ACTUAL_SIZE) << 1))

/**
 * @brief
 * 	Total memory mapped
 */
#define	MSGCOMM_MMAP_TOTAL																		\
	(																							\
		(MSGCOMM_MSGCOMM_MEMORY_SIZE) + (MSGCOMM_SPACE_SIZE) + (MSGCOMM_CMDMEM_SIZE) +			\
		(MSGCOMM_CPINFO_SIZE) + (MSGCOMM_MEMFLAG_SIZE) + (MSGCOMM_RESERVE_SIZE) +				\
		(MSGCOMM_ARGV_SIZE) + (MSGCOMM_PKTPTRARR_SIZE) + (MSGCOMM_BUFFER_SIZE) +				\
		(MSGCOMM_REPLY_SIZE)																	\
	)																							\


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
	int
	msgcomm_startup(void);


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