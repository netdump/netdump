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

#ifndef __C2A_COMM_H__
#define __C2A_COMM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap.h"
#include "common.h"


/**
 * @brief
 *  Storing captured packets
 * @memberof pkthdr
 *  Capture packet information
 * @memberof data
 *  Original packet content
 */
typedef struct datastore_s 
{
    struct pcap_pkthdr pkthdr;
    unsigned char data[0];
} datastore_t;

extern NETDUMP_SHARED ALIGN_CACHELINE unsigned int capture_notify_analysis;

/**
 * @brief Global ctoa shared memory pointer variable
 */
extern void * c2a_shm_addr;


/**
 * @brief Global ctoa shared memory, Capture process write data pointer
 */
extern void *c2a_shm_write_addr;


/**
 * @brief Global ctoa shared memory, Capture process read data pointer
 */
extern void *c2a_shm_read_addr;


/**
 * @brief ctoa shared memory file path
 */
#define C2A_COMM_SHM_FILEPATH                   "/var/log/netdump/"


/**
 * @brief ctoa shared memory file name
 */
#define C2A_COMM_SHM_FILENAME                   ".ctoacomm.mem"


/**
 * @brief Full file name
 */
#define C2A_COMM_SHM_FULLNAME                   "/var/log/netdump/.ctoacomm.mem"


/**
 * @brief ctoa shared memory file size
 */
#define C2A_COMM_SHM_FILESIZE                   ((1<<30))


/**
 * @brief ctoa shared memory starting base address
 */
#define C2A_COMM_SHM_BASEADDR                   ((void *)(0x6EEE00000000))


/**
 * @brief
 *  Make memory address 8-byte aligned
 */
#define C2A_COMM_ADDR_ALIGN(address)            (((uintptr_t)(address) + 7) & ~(7))

/**
 * @brief
 * this structure stores the offset of the current block relative to the start of the file after mmap memory mapping,
 * as well as the start and end indices of the network frames stored in the current block.
 * @memberof offset
 *  the offset of the current block relative to the start of the file
 * @memberof start_idx
 *  the start indices of the network frames stored in the current block
 * @memberof end_idx
 *  the end indices of the network frames stored in the current block
 * @memberof seq
 *  sequence counter
 */
typedef struct ALIGN_CACHELINE {
    uint32_t offset;
    uint32_t start_idx;
    uint32_t end_idx;
    uint32_t seq;
} c2a_memory_block_management_t;


#define C2A_MAX_BLOCK_NUMS      256
extern NETDUMP_SHARED ALIGN_PAGE c2a_memory_block_management_t c2a_mem_block_management[C2A_MAX_BLOCK_NUMS];

/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int c2a_comm_startup(void);

/**
 * @brief
 *  Inter-process communication resource destruction operation
 */
void c2a_comm_ending(void);

/**
 * @brief
 *  Load the mapped memory into the memory page
 */
void c2a_comm_memory_load(void);

#endif // __C2A_COMM_H__