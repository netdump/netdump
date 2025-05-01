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


#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
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
#include <setjmp.h>

#include "bpf.h"
#include "pcap/pcap.h"
#include "pcap/dlt.h"

#include "common.h"
#include "ring.h"


#define IF_PRINTER_ARGS (void *, const struct pcap_pkthdr *, const unsigned char *)

typedef void(*if_printer) IF_PRINTER_ARGS;

/*
 * In case the data in a buffer needs to be processed by being decrypted,
 * decompressed, etc. before it's dissected, we can't process it in place,
 * we have to allocate a new buffer for the processed data.
 *
 * We keep a stack of those buffers; when we allocate a new buffer, we
 * push the current one onto a stack, and when we're done with the new
 * buffer, we free the current buffer and pop the previous one off the
 * stack.
 *
 * A buffer has a beginning and end pointer, and a link to the previous
 * buffer on the stack.
 *
 * In other cases, we temporarily adjust the snapshot end to reflect a
 * packet-length field in the packet data and, when finished dissecting
 * that part of the packet, restore the old snapshot end.  We keep that
 * on the stack with null buffer pointer, meaning there's nothing to
 * free.
 */
struct netdissect_saved_packet_info
{
	unsigned char *ndspi_buffer;					 /* pointer to allocated buffer data */
	const unsigned char *ndspi_packetp;				 /* saved beginning of data */
	const unsigned char *ndspi_snapend;				 /* saved end of data */
	struct netdissect_saved_packet_info *ndspi_prev; /* previous buffer on the stack */
};

/* 'val' value(s) for longjmp */
#define ND_TRUNCATED 1

typedef struct ndo_s
{
	int ndo_bflag;					/* print 4 byte ASes in ASDOT notation */
	int ndo_eflag;					/* print ethernet header */
	int ndo_fflag;					/* don't translate "foreign" IP address */
	int ndo_Kflag;					/* don't check IP, TCP or UDP checksums */
	int ndo_nflag;					/* leave addresses as numbers */
	int ndo_Nflag;					/* remove domains from printed host names */
	int ndo_qflag;					/* quick (shorter) output */
	int ndo_Sflag;					/* print raw TCP sequence numbers */
	int ndo_tflag;					/* print packet arrival time */
	int ndo_uflag;					/* Print undecoded NFS handles */
	int ndo_vflag;					/* verbosity level */
	int ndo_xflag;					/* print packet in hex */
	int ndo_Xflag;					/* print packet in hex/ASCII */
	int ndo_Aflag;					/* print packet only in ASCII observing TAB,
									 * LF, CR and SPACE as graphical chars
									 */
	int ndo_Hflag;					/* dissect 802.11s draft mesh standard */
	const char *ndo_protocol;		/* protocol */
	jmp_buf ndo_early_end;			/* jmp_buf for setjmp()/longjmp() */
	void *ndo_last_mem_p;			/* pointer to the last allocated memory chunk */
	int ndo_packet_number;			/* print a packet number in the beginning of line */
	int ndo_suppress_default_print; /* don't use default_print() for unknown packet types */
	int ndo_tstamp_precision;		/* requested time stamp precision */
	const char *program_name;		/* Name of the program using the library */

	char *ndo_espsecret;
	struct sa_list *ndo_sa_list_head; /* used by print-esp.c */
	struct sa_list *ndo_sa_default;

	char *ndo_sigsecret; /* Signature verification secret key */

	int ndo_packettype; /* as specified by -T */

	int ndo_snaplen;
	int ndo_ll_hdr_len; /* link-layer header length */

	/*global pointers to beginning and end of current packet (during printing) */
	const unsigned char *ndo_packetp;
	const unsigned char *ndo_snapend;

	/* stack of saved packet boundary and buffer information */
	struct netdissect_saved_packet_info *ndo_packet_info_stack;

	/* pointer to the if_printer function */
	if_printer ndo_if_printer;

#if 0
	/* pointer to void function to output stuff */
	void (*ndo_default_print)(netdissect_options *,
				const unsigned char *bp, unsigned int length);

	/* pointer to function to do regular output */
	int  (*ndo_printf)(netdissect_options *,
				const char *fmt, ...)
				PRINTFLIKE_FUNCPTR(2, 3);
	/* pointer to function to output errors */
	void NORETURN_FUNCPTR (*ndo_error)(netdissect_options *,
						status_exit_codes_t status,
						const char *fmt, ...)
						PRINTFLIKE_FUNCPTR(3, 4);
	/* pointer to function to output warnings */
	void (*ndo_warning)(netdissect_options *,
				const char *fmt, ...)
				PRINTFLIKE_FUNCPTR(2, 3);
#endif
} ndo_t;


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
#define MSGCOMM_MEMORY_SPACE					(1 << 11)


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
 * @memberof cmdbuf
 * 	store string that need to compile, used for bpf
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
	void * cmdbuf;
	void * cpinfo;
	void ** argv;
	void * memflag;
	void * ndo;

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
 * 	Mainly used in the capture process to receive messages from the display process
 */
#define msgcomm_G_cmdbuf 				(memcomm.cmdbuf)

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
 * 	Pointer array to store the parsed command string
 */
#define msgcomm_G_argv					(memcomm.argv)


/**
 * @brief
 * 	ctoa ndo variable
 */
#define msgcomm_G_ndo					(memcomm.ndo)


/**
 * @brief
 * 	memcomm.buffer size
 */
#define MSGCOMM_BUFFER_SIZE						(1 << 11)	// 2048

/**
 * @brief
 * 	memcomm.reply size
 */
#define MSGCOMM_REPLY_SIZE						(1 << 11)	// 2048

/**
 * @brief
 * 	memcomm_t.space size
 */
#define MSGCOMM_SPACE_SIZE 						(1 << 11)	// 2048

/**
 * @brief
 * 	memcomm_t.cmdmem size
 */
#define MSGCOMM_CMDMEM_SIZE 					(1 << 11)	// 2048

/**
 * @brief
 * 	memcomm_t.cmdbuf size
 */
#define MSGCOMM_CMDBUF_SIZE 					(1 << 11) 	// 2048

/**
 * @brief
 * 	memcomm_t.cpinfo size
 */
#define MSGCOMM_CPINFO_SIZE 					(1 << 11)	// 2048

/**
 * @brief
 * 	memcomm_t.memflag size
 */
#define MSGCOMM_MEMFLAG_SIZE 					(1 << 8)	// 256


/**
 * @brief
 * 	memcomm_t.argv size
 */
#define MSGCOMM_ARGV_SIZE 						(1 << 11) 	// 2048


/**
 * @brief
 * 	Memory length after rounding 4096
 */
#define MSGCOMM_RING_T_SIZE						(((((sizeof(ring_t)) + (MSGCOMM_BLOCK_NUMBERS << 3)) >> 11) + 1) << 11)


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
 * 	ctoa ndo memory size
 */
#define MSGCOMM_CTOA_NDO_MEMORY_SIZE			(2048)


/**
 * @brief
 * 	Total memory mapped
 */
#define	MSGCOMM_MMAP_TOTAL																		\
	(																							\
		(MSGCOMM_MSGCOMM_MEMORY_SIZE) + (MSGCOMM_SPACE_SIZE) + (MSGCOMM_CMDMEM_SIZE) +			\
		(MSGCOMM_CPINFO_SIZE) + (MSGCOMM_MEMFLAG_SIZE) + /*(MSGCOMM_RESERVE_SIZE) +	*/			\
		(MSGCOMM_ARGV_SIZE) + /*(MSGCOMM_PKTPTRARR_SIZE) + */(MSGCOMM_BUFFER_SIZE) +			\
		(MSGCOMM_REPLY_SIZE) + (MSGCOMM_CMDBUF_SIZE) + (MSGCOMM_CTOA_NDO_MEMORY_SIZE)			\
	)


/**
 * @brief
 * 	State transfer structure
 * @memberof _runflag_
 * 	Stores the pause status value
 * 	Stores the continue status value
 * 	Store exit status value
 * @memberof _top
 * 	Store the top status value
 * @memberof _bottom
 * 	Store the bottom status value
 * @memberof _win3_curline
 * 	Current line number of window 3
 * @memberof _win4_curline
 *	Current line number of window 4
 * @memberof _win5_curline
 *	Current line number of window 5
 * @memberof _cppc
 * 	Command parameter parsing completed
 * @memberof padding
 *	padding
 * @memberof _G_CPnumber
 * 	Current page number
 * @memberof _G_CSnumber
 *	Global scope index
 * @memberof _C_CSnumber
 * 	Indexes in the cache
 * @memberof _NOpackages
 * 	Number of packages
 * @memberof _NObytes
 * 	Number of bytes
 * @memberof _reserve
 * 	Retention and filling
 * @note
 *	[ _runflag_ ] from DP to CP ;
 * 	[ _runflag_c2d ] from CP to DP ;
 *	[ cppc ] from CP to AA
 *	[ _G_CSnumber & _C_CSnumber ] from DP to CP
 *	[ _NOpackages & _NObytes ] from CP to DP ;
 */
typedef struct {

	volatile unsigned short _runflag_;
	volatile unsigned short _runflag_c2d;

	volatile unsigned char _top;
	volatile unsigned char _bottom;
	volatile unsigned char _win3_curline;
	volatile unsigned char _win4_curline;

	volatile unsigned char _win5_curline;

	volatile unsigned char _cppc;
	volatile unsigned char _padding[6];

	volatile unsigned long _G_CPnumber;
	volatile unsigned long _G_CSnumber;
	volatile unsigned long _C_CSnumber;
	volatile unsigned long _NOpackages;
	volatile unsigned long _NObytes;
	volatile unsigned char _reserve[200];

} _status_t;


/**
 * @brief
 *  Global pointer to (struct _status_t) type
 */
extern _status_t * G_status_ptr;


/**
 * @brief Clear the global status value
 */
#define msgcomm_clear_G_status()												\
	do {																		\
		memset(G_status_ptr, 0, sizeof(_status_t));								\
		__atomic_thread_fence(__ATOMIC_RELEASE);								\
	} while (0);


/**
 * @brief
 * 	The address of _runflag_
 * @note
 * 	A value of 1 means pause
 * 	A value of 2 means continue
 * 	A value of 4 means exit.
 * 	A value of 8 means save & exit.
 */
#define msgcomm_st_runflag					(&(G_status_ptr->_runflag_))


/**
 * @brief Pause Value
 */
#define MSGCOMM_ST_PAUSE					(0x01)			


/**
 * @brief Continue Value
 */
#define MSGCOMM_ST_CONTINUE					(0x02)


/**
 * @brief Exit Value
 */
#define MSGCOMM_ST_EXIT						(0x04)


/**
 * @brief Save Value
 */
#define MSGCOMM_ST_SAVE						(0x08)


/**
 * @brief The address of _runflag_ capture to display
 */
#define msgcomm_st_runflag_c2d				(&(G_status_ptr->_runflag_c2d))


/**
 * @brief Unable to obtain a valid file descriptor
 */
#define MSGCOMM_ST_C2D_FD_ERR				(0x01)


/**
 * @brief pcap_breakloop function is called
 */
#define MSGCOMM_ST_C2D_PCAP_BREAKLOOP_ERR	(0x02)


/**
 * @brief pcap_dispatch function error
 */
#define MSGCOMM_ST_C2D_PCAP_DISPATCH_ERR	(0x04)


/**
 * @brief poll function error
 */
#define MSGCOMM_ST_C2D_POLL_ERR				(0x08)


/**
 * @brief The address of _cppc
 */
#define msgcomm_st_cppc						(&(G_status_ptr->_cppc))


/**
 * @brief CPPC Value
 * @note 1 indicates command parameter parsing is complete
 */
#define MSGCOMM_ST_CPPC						(0x01)


/**
 * @brief
 * 	The address of _NOpackages
 */
#define msgcomm_st_NOpackages				(&(G_status_ptr->_NOpackages))


/**
 * @brief
 * 	The address of _NObytes
 */
#define msgcomm_st_NObytes					(&(G_status_ptr->_NObytes))


/**
 * @brief
 * 	Passing state values ​​between processes
 * @param address
 * 	The address of the state variable to be passed
 * @param value
 * 	The state value that needs to be passed
 */
#define msgcomm_transfer_status_change(address, value)											\
	do {																						\
		__atomic_store_n((address), value, __ATOMIC_RELEASE);									\
		/*__atomic_thread_fence(__ATOMIC_RELEASE);*/											\
	} while (0);


/**
 * @brief
 * 	Receive the transmitted status value
 * @param address
 * 	Get the address of the status value
 * @param variable
 * 	Store the obtained status value
 */
#define msgcomm_receive_status_value(address, variable)											\
	do {																						\
		/*__atomic_thread_fence(__ATOMIC_ACQUIRE);*/											\
		variable = __atomic_load_n(address, __ATOMIC_ACQUIRE);									\
	} while (0);


/**
 * @brief
 * 	Adds a value to the specified variable.
 * @param address
 * 	Specify the address of the data
 * @param value
 *	Accumulated value
 */
#define msgcomm_increase_data_value(address, value)												\
	do {																						\
		__atomic_fetch_add(address, value, __ATOMIC_SEQ_CST);									\
	} while(0);


/**
 * @brief
 * 	Sets the specified variable to zero
 * @param address
 * 	Specify the address of the data
 */
#define msgcomm_zero_variable(address)															\
	do {																						\
		__atomic_store_n(address, 0, __ATOMIC_SEQ_CST);											\
	} while(0);


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