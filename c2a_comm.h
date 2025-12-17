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
#include <sys/statfs.h>
#include <linux/magic.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <stdint.h>
#include <errno.h>

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

/*********************************************************************************/

/* 分割线中的内容在修改完后会删除 */

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
#define C2A_COMM_SHM_BASEADDR                   ((void *)(0x6EEA00000000))

/*********************************************************************************/

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
 * @note
 *  The significance of this structure may not be very high at present. 
 *  We'll keep it for now. Later, when a fast search function is needed, 
 *  this structure will prove valuable.
 */
typedef struct ALIGN_CACHELINE {
    uint64_t offset;
    uint64_t start_idx;
    uint64_t end_idx;
    void * used_fixed_addr;
    uint32_t isfull;
    char pad[CACHELINE - 3 * sizeof(uint64_t) - sizeof(uint32_t) - sizeof(void *)];
} c2a_memory_block_meta_t;

_Static_assert(sizeof(c2a_memory_block_meta_t) == CACHELINE, "meta block must be cacheline sized");

#define C2A_MAX_BLOCK_NUMS      256
extern NETDUMP_SHARED ALIGN_PAGE c2a_memory_block_meta_t c2a_mem_block_management[C2A_MAX_BLOCK_NUMS];

#define C2A_COMM_SHM_STORE_FILE_PATH                "/var/lib/netdump"

#define C2A_COMM_SHM_STORE_FILE_NAME                ".netdump_store"

#define C2A_COMM_SHM_STORE_ABSOLUTE_FN              "/var/lib/netdump/.netdump_store"

#define GiB_SHIFT                                   (30)

#define C2A_COMM_SHM_STORE_FILE_MIN_SIZE            (16)
#define C2A_COMM_SHM_STORE_FILE_MAX_SIZE            (256)

// The number of array elements is obtained by calculating how many 64-byte network frames can be stored on 256MB.
#define C2A_COMM_MEM_BLOCK_ELEMENT_NUMS             (1 << 22) // (4 * 1024 * 1024)  
#define C2A_COMM_MEM_BLOCK_DATA_ZONE_SZ             (((1<< 4) - 1) << 24) // (256MB - 16MB)
#define C2A_COMM_MEM_BLOCK_ZONE_SIZE                (1 << 28) // 256MB

/**
 * @memberof remain_zone remaining space in the current block
 * @memberof next_idx
 *  The index of the per_frame_offset array points to the next usable array element.
 * @memberof pkts_start_sn
 *  The sequence number of the starting data packet in this data block
 * @memberof pkts_end_sn
 *  The sequence number of the end packet in this data block
 * @memberof offset
 *  Offset relative to the start of the file
 * @memberof block_meta_idx
 *  Index in array c2a_mem_block_management
 * @memberof isfull
 *  Is the data block full? 1 is full
 */
typedef struct c2a_comm_ctrl {
    uint32_t remain_zone;
    uint32_t next_idx;
    uint64_t pkts_start_sn;
    uint64_t pkts_end_sn;
    uint64_t offset;
    void * used_fixed_addr;
    uint32_t block_meta_idx;
    uint32_t isfull;
    char pad[CACHELINE - 4 * sizeof(uint32_t) - 3 * sizeof(uint64_t) - sizeof(void *)];
} ALIGN_CACHELINE c2a_comm_ctrl_t;

_Static_assert(sizeof(c2a_comm_ctrl_t) == CACHELINE, "ctrl size error");

#define CTRL_SIZE               sizeof(c2a_comm_ctrl_t)
#define OFFSET_TABLE_SIZE       (sizeof(int) * C2A_COMM_MEM_BLOCK_ELEMENT_NUMS)

/**
 * @memberof per_frame_offset
 *  the offset of each frame relative to the starting position
 * @memberof per_frame_data
 *  store each frame sequentially
 */
typedef struct c2a_comm_mem_block {
    c2a_comm_ctrl_t crtl;
    int per_frame_offset[C2A_COMM_MEM_BLOCK_ELEMENT_NUMS];
    char per_frame_data[C2A_COMM_MEM_BLOCK_ZONE_SIZE - OFFSET_TABLE_SIZE - CTRL_SIZE];
} c2a_comm_mem_block_t;

_Static_assert(
    CTRL_SIZE + OFFSET_TABLE_SIZE + sizeof(((c2a_comm_mem_block_t *)0)->per_frame_data) ==
        C2A_COMM_MEM_BLOCK_ZONE_SIZE, "block size mismatch"
    );

#define C2A_COMM_MEM_BLOCK_0_BASE_ADDR          ((void *)(0x700000000000))
#define C2A_COMM_MEM_BLOCK_1_BASE_ADDR          ((void *)(0x700040000000))
#define C2A_COMM_MEM_BLOCK_2_BASE_ADDR          ((void *)(0x700080000000))

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
 * @brief initialization mem_block_management
 */
void c2a_comm_mem_block_management_init(void);

/**
 * @brief block0 used for initializing the parsing process
 */
int c2a_comm_block_0_init(void);

/**
 * @brief Blocks 1 and 2 used to initialize the capture process
 */
int c2a_comm_block_1_block_2_init(void);

/**
 * @brief
 *  Load the mapped memory into the memory page
 */
void c2a_comm_memory_load(void);

#if 0
1. statfs → 校验文件系统
2. statvfs → 校验可用空间
3. ftruncate(64GB)
4. 校验 sparse file
#endif
/**
 * @brief u
 *  sed to test file systems, verify available space, and check for sparse files.
 * @return
 *  returns ND_OK on success, ND_ERR on failure.
 * @note
 *  if any non-compliance is detected, the program will exit immediately.
 */
int c2a_check_fs_vfs_sparse(void);

#endif // __C2A_COMM_H__