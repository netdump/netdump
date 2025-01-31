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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

/**
 * @brief 
 *  Major version number
 */
#define NETDUMP_MAJOR_VERSION           0x0001U
#define MAJOR_V                         NETDUMP_MAJOR_VERSION
/**
 * @brief 
 *  Subversion number
 */
#define NETDUMP_SUB_VERSION             0x0001U
#define SUB_V                           NETDUMP_SUB_VERSION


/** C99：编译时使用 -std=c99，编译器会定义 __STDC_VERSION__ 宏为 199901L */
/** C89：编译时使用 -std=c89，编译器会定义 __STDC_VERSION__ 宏为 199409L */
/** C99 */
#if __STDC_VERSION__ >= 199901L

#include <stdint.h>
#include <stdbool.h>

#else 

#define true                1
#define false               0

typedef char                int8_t;
typedef unsigned char       uint8_t;
typedef unsigned char       bool;

typedef char *              int8_t *;

typedef short               int16_t;
typedef unsigned short      uint16_t;

typedef int                 int32_t;
typedef unsigned int        uint32_t;

typedef long long           int64_t;
typedef unsigned long long  uint64_t;

#endif



/**
 * @brief 
 *  Error Code
 * @memberof ND_OK
 *  Indicates success
 * @memberof ND_ERR
 *  Indicates failure
 */
enum {
    ND_OK,
    ND_ERR,
};


/**
 * @brief
 *  The ID of each process
 * @memberof GCOREID_DP
 *  DISPLAY PROCESS ID
 * @memberof GCOREID_CP
 *  CAPTURE PROCESS ID
 * @memberof GCOREID_AA
 *  ANALYSIS PROCESS ID
 */
/** DISPLAY PROCESS ID */
#define GCOREID_DP      0U
/** CAPTURE PROCESS ID */
#define GCOREID_CP      1U
/** ANALYSIS PROCESS ID */
#define GCOREID_AA      2U


/**
 * @brief 
 *  Global process number
 */
extern uint32_t GCOREID;

/**
 * @brief 
 *  Get the GCOREID of the current process
 */
__extern_always_inline uint32_t lcore_id(void) {

    return GCOREID;
}


/**
 * @brief 
 *  Check if the kernel version is greater than 2.6.6 
 * @note
 *  If the kernel version is less than 2.6.6, 
 *  the program will exit because the program uses mq_open and other related APIs.
 */
void nd_check_kernel_version(void);


/**
 * @brief 
 *  Check if the kernel version is greater than 2.6.6 
 */
#define ND_CHECK_KERNEL_VERSION()   do{nd_check_kernel_version();} while(0);


/**
 * Check if a branch is likely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * likely to be taken. Example:
 *
 *   if (likely(x > 1))
 *      do_stuff();
 *
 */
#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif /* likely */

/**
 * Check if a branch is unlikely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * unlikely to be taken. Example:
 *
 *   if (unlikely(x < 1))
 *      do_stuff();
 *
 */
#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif /* unlikely */


/**
 * @brief 
 * 	true if x is a power of 2
 */
#ifndef POWEROF2
#define POWEROF2(x) ((((x)-1) & (x)) == 0)
#endif /* POWEROF2 */


/**
 * @brief 
 * 	It is to page align the incoming address addr
 * @param addr 
 * 	 Addresses that need to be aligned
 * @return 
 * 	Returns a page-aligned address
 */
uintptr_t align_address(uintptr_t addr);


/**
 * @brief 
 *  The maximum space occupied by the communication file name
 */
#define COMM_NAMESIZE	256


/**
 * @brief 
 *  Common structures for communication
 * @memberof ring
 *  A circular queue for storing communication data during communication
 * @memberof _ring
 *  A circular queue that stores unused data space during communication
 * @memberof memery
 *  The memory start address corresponding to the ring
 * @memberof _memery
 *  The memory start address corresponding to the _ring
 * @memberof baseaddr
 *  The base address used when the ring is initialized
 * @memberof _baseaddr
 *  The base address used when the _ring is initialized
 * @memberof count
 *  The number of elements in the circular queue
 * @memberof name
 *  The file name corresponding to ring
 * @memberof _name
 *  The file name corresponding to _ring
 */
typedef struct {
	
    void * ring;
	void * _ring;

	void * memery;
	void * _memery;
	
	void * baseaddr;
	void * _baseaddr;

    unsigned long long count;
	
	char name[COMM_NAMESIZE];
	char _name[COMM_NAMESIZE];

} comm_t;


/**
 * @brief 
 *  Check if the directory containing the file name exists; 
 *  Check if the directory containing the file name is writable; 
 *  Check if the directory containing the file name is readable; 
 *  Delete the file if it exists
 * @param fname
 *  The file name to be checked
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int nd_check_fpath (char * fname);


/**
 * @brief
 *  Call the mmap function to open up memory space
 * @param name
 *  The name of the file
 * @param baseaddr
 *  Starting base address
 * @param memspace
 *  The size of each memory block
 * @param count
 *  Number of memory blocks
 * @return 
 *  Returns the address of the allocated space if successful, 
 *  otherwise returns NULL
 */
void * nd_called_open_mmap_openup_memory (
	const char * name, void * baseaddr, unsigned int memspace, unsigned int count);


/**
 * @brief
 *  Call the mmap function to look up memory space
 * @param name
 *  The name of the file
 * @param baseaddr
 *  Starting base address
 * @param memspace
 *  The size of each memory block
 * @param count
 *  Number of memory blocks
 * @return 
 *  Returns the address of the allocated space if successful, 
 *  otherwise returns NULL
 */
void * nd_called_mmap_lookup_memory (
	const char * name, void * baseaddr, unsigned int memspace, unsigned int count);

#endif 