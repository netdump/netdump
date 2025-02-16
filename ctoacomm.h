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
 * @brief Global ctoa shared memory pointer variable
 */
extern void * G_ctoa_shm_mem;


/**
 * @brief Global ctoa shared memory cursor
 */
extern void * G_ctos_shm_mem_cursor;


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
#define CTOACOMM_SHM_FILESIZE                   ((1ULL << 32))


/**
 * @brief ctoa shared memory starting base address
 */
#define CTOACOMM_SHM_BASEADDR                   ((void *)(0x6EEE00000000))


#endif  // __CTOACOMM_H__