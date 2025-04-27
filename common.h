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

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <fcntl.h>
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
	CP_FAD,
};


/**
 * @brief
 * 	Doubly Linked List
 */
typedef struct nd_dll_s
{
	void * prev;
	void * next;
} nd_dll_t;


/**
 * @brief
 * 	Calculate the structure address through the member address and offset
 */
#define container_of(ptr, type, member)		((type *)((char *)(ptr) - offsetof(type, member)))


/**
 * @brief
 * 	Get the minimum value
 */
#define min(x, y) ({ typeof(x) _x = (x); typeof(y) _y = (y); _x < _y ? _x : _y; })


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


/** A string containing the name of the netdump process */
#define NETDUMP_NAME			"netdump"

#define COMMON_SPACE			" "

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
 *  Array storing the pid value of the child process
 */
extern pid_t childpid[3];


/**
 * @brief 
 * 	Define a function pointer to use when creating a process
 */
typedef int (*funcpointer) (unsigned int, const char *, void *);


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
 * 	Check if it is aligned relative to a value
 * The value must be an exponent of 2.
 */
#define COMM_ALIGNED_VALUE(detected, value)					(((unsigned long long)(detected) & ((value) - 1)))
															


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
	
	//void * baseaddr;
	//void * _baseaddr;

    unsigned long long count;
	
	//char name[COMM_NAMESIZE];
	//char _name[COMM_NAMESIZE];

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


/** =========================================================================================== */
/**
 * @brief The code between the dividing lines is about hugepage.
 */


#include <sys/mount.h>


/**
 * @brief
 *  Set the file for transparent large pages
 */
#define ND_THP_DISABLE_PATH 												"/sys/kernel/mm/transparent_hugepage/enabled"


/**
 * @brief
 *  Disable command strings for transparent large pages
 */
#define ND_THP_DISABLE_CMD_STRING 											"never"


/**
 * @brief
 *  Multi-size large page support
 */
enum hugepage_size
{
	HUGEPAGE_2MB = 2048,
	HUGEPAGE_1GB = 1048576
};


/**
 * @brief
 *  Sets the file path format for large page memory
 */
#define ND_HUGEPAGE_SYS_PATH_FORMAT 										"/sys/kernel/mm/hugepages/hugepages-%dkB/nr_hugepages"


/**
 * @brief
 *  The old way of setting up large page memory
 */
#define ND_HUGEPAGE_OLD_WAY_SETUP 											"/proc/sys/vm/nr_hugepages"


/**
 * @brief
 *  Large page mount point
 */
#define ND_HUGETLB_MOUNT_POINT 												"/mnt/huge"


/**
 * @brief
 *  A file that obtains file system mount information
 */
#define ND_SYS_PROC_MOUNT_INFO 												"/proc/mounts"


/**
 * @brief Global storage mount point space
 */
#define nd_G_store_mountpoint_space         								128


/**
 * @brief
 *  A file that contains system-level memory information
 */
#define ND_SYS_PROC_MEMORY_INFO 											"/proc/meminfo"


/**
 * @brief
 *  Set the status of transparent pages to Forbidden state
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_disable_transparent_hugepages(void);


/**
 * @brief
 *  Restore the system's transparent large page settings
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_recover_transparent_hugepages(void);


/**
 * @brief
 *  Compatible with the old kernel's large page count setting
 * @param pages
 *  The value that needs to be set
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_set_hugepages_legacy(int pages);


/**
 * @brief
 *  Compatible with large page count reads from older kernels
 * @return
 *  The amount of the original large page memory successfully returned
 *  Failure returns -1
 */
int nd_get_current_hugepages_legacy(void);


/**
 * @brief
 *  Use the sysfs type interface to set the large page memory
 * @param delta_pages
 *  The incremental value of the large page memory
 * @param sys_path
 *  Use the sysfs type interface to set the file path used by large page memory
 * @return
 *  Failure returns 0x7FFFFFFF
 *  When the value of parameter delta_pages is returned, it indicates complete success
 *  If the returned value is a different value, it indicates that a part of the increment has been added
 */
int nd_set_hugepages_use_sysfs_interface(int delta_pages, char *sys_path);


/**
 * @brief
 *  Set the large page memory increment
 * @param delta_pages
 *  The incremental value of the large page memory
 * @param size
 *  The size of the large page memory
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_set_hugepages_incremental(int delta_pages, enum hugepage_size size);


/**
 * @brief
 *  Check if the directory exists
 * @param path
 *  The path that needs to be detected
 * @return
 *  1 is returned for success
 *  0 is returned for failure
 */
int nd_dir_exists(const char *path);


/**
 * @brief
 *  Create a directory (recursively, similar to mkdir -p)
 * @param path
 *  A directory that needs to be created
 * @return
 *  Returns 0 for success
 *  Returns -1 for failure
 */
int nd_mkdir_p(const char *path);


/**
 * @brief
 *  Check if hugetlbfs is mounted to the target path
 * @return
 *  Function execution failure returns -1
 *  Returns 0 if not mounted
 *  Mount returns 1
 */
int nd_is_hugetlbfs_mounted(void);


/**
 * @brief
 *  Mounting Hugetlbfs (Requires Root Privilege)
 * @return
 *  Returns 0 for success
 *  Returns -1 for failure
 */
int nd_mount_hugetlbfs(void);


/**
 * @brief
 *  Read the /proc/meminfo file to verify that the large page memory is set
 * @param Rtotal
 *  The total number of hugepages is stored.
 * @param Rfree
 *  Stores the total number of HugePage idle.
 * @return
 *  Returns 0 for success
 *  Returns -1 for failure
 */
int nd_validate_hugepage_distribution(int *Rtotal, int *Rfree);


/**
 * @brief
 *  Sets large page memory globally
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int nd_Global_set_hugepage_memory(void);


/**
 * @brief
 *  Global fallback settings for large page memory
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int nd_fallback_hugepage_setting (void);


/** =========================================================================================== */

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
	const char * name, void * baseaddr, unsigned long long memspace, unsigned int count);

	
/**
 * @brief
 *  Call the mmap function to open up memory space
 * @param name
 *  The name of the file
 * @param baseaddr
 *  Starting base address
 * @param memspace
 *  The size of memory
 * @return
 *  Returns the address of the allocated space if successful,
 *  otherwise returns NULL
 */
void *nd_called_shmopen_mmap_openup_memory(
	const char *name, void *baseaddr, unsigned int memsize);


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


/**
 * @brief 
 *  Use the select function to achieve millisecond delay
 * @param sec
 *  Delay in second
 * @param microseconds
 *  Delay in microseconds
 */
void nd_delay_microsecond (unsigned int sec, unsigned long microseconds);


/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
/**
 * @brief
 *  Copy src to string dst of size siz.
 * @param dst
 *  dst addr
 * @param src
 *  src addr
 * @param siz
 *  length
 * @return
 *  copy length
 */
size_t strlcpy(char *dst, const char *src, size_t siz);


/**
 * @brief
 *  Take the node from the head of the doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t * nd_dll_takeout_from_head(nd_dll_t ** head);


/**
 * @brief
 *  Take the node from the tail of the doubly linked list
 * @memberof tail
 *  the tail of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t *nd_dll_takeout_from_tail(nd_dll_t ** tail);


/**
 * @brief
 *  Insert the head of a doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int nd_dll_intset_into_head(nd_dll_t ** head, nd_dll_t * node);


/**
 * @brief
 *  Insert the tail of a doubly linked list
 * @memberof tail
 *  the tail of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int nd_dll_insert_into_tail(nd_dll_t ** tail, nd_dll_t * node);

#endif 