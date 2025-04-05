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

#ifndef __CTOACOMM_H__
#define __CTOACOMM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap.h"
#include "common.h"
#include "ring.h"


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


/**
 * @brief Global ctoa shared memory pointer variable
 */
extern void * G_ctoa_shm_mem;


/**
 * @brief Global ctoa shared memory, Capture process write data pointer
 */
extern void *G_ctoa_shm_mem_wp;


/**
 * @brief Global ctoa shared memory, Capture process read data pointer
 */
extern void *G_ctoa_shm_mem_rp;


/**
 * @brief ctoa shared memory file path
 */
#define CTOACOMM_SHM_FILEPATH                   "/var/log/netdump/"


/**
 * @brief ctoa shared memory file name
 */
#define CTOACOMM_SHM_FILENAME                   ".ctoacomm.mem"


/**
 * @brief Full file name
 */
#define CTOACOMM_SHM_FULLNAME                   "/var/log/netdump/.ctoacomm.mem"


/**
 * @brief ctoa shared memory file size
 */
#define CTOACOMM_SHM_FILESIZE                   ((1ULL << 31))


/**
 * @brief ctoa shared memory starting base address
 */
#define CTOACOMM_SHM_BASEADDR                   ((void *)(0x6EEE00000000))


/**
 * @brief
 *  Make memory address 8-byte aligned
 */
#define CTOACOMM_ADDR_ALIGN(address)            (((uintptr_t)(address) + 7) & ~(7))


/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int ctoacomm_startup(void);


/**
 * @brief
 *  Inter-process communication resource destruction operation
 */
void ctoacomm_ending(void);


/**
 * @brief
 *  Load the mapped memory into the memory page
 */
void ctoacomm_memory_load(void);

#endif  // __CTOACOMM_H__