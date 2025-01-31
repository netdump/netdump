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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <linux/version.h>
#include "trace.h"
#include "common.h"


/**
 * @brief 
 *  Global process number
 */
uint32_t GCOREID = 0;


/**
 * @brief 
 *  Array storing the pid value of the child process
 */
pid_t childpid[3] = {0, 0, 0};


/**
 * @brief 
 *  Check if the kernel version is greater than 2.6.6 
 * @note
 *  If the kernel version is less than 2.6.6, 
 *  the program will exit because the program uses mq_open and other related APIs.
 */
void nd_check_kernel_version(void) {

    if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 6)) {
        fprintf(stderr, "Kernel version is less than 2.6.6\n");
        exit(1);
    }
    return ;
}


/**
 * @brief 
 * 	It is to page align the incoming address addr
 * @param addr 
 * 	 Addresses that need to be aligned
 * @return 
 * 	Returns a page-aligned address
 */
uintptr_t align_address(uintptr_t addr)
{
	TC("Called { %s(%p)", __func__, addr);

    long page_size = sysconf(_SC_PAGESIZE); 

    if (unlikely(page_size == -1)) {
		T("errmsg: %s", strerror(errno));
        page_size = 4096;
	}

	RVoidPtr(((addr + page_size - 1) & ~(page_size - 1)));
}


/**
 * @brief 
 *  Check if the directory exists and create it if it does not exist
 * @param fpath
 *  File path pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int nd_check_directory(const char *fpath) {

    TC("Called { %s(%p)", __func__, fpath);

    struct stat statbuf;
    if (unlikely(((stat(fpath, &statbuf)) == -1))) {
        if (unlikely((mkdir(fpath, 0755)) == -1)) {
            T("errmsg: %s", strerror(errno));
            RInt(ND_ERR);
        }
        T("infomsg: directory created: %s", fpath);
    } else if (S_ISDIR(statbuf.st_mode)) {
        T("infomsg: directory exists: %s", fpath);
    } else {
        T("infomsg: Path exists but is not a directory: %s", fpath);
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Check if the file exists, and delete it if it does exist
 * @param file
 *  File name pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int check_and_delete_file(const char *fname) {

    TC("Called { %s(%p)", __func__, fname);

    if (access(fname, F_OK) == 0) {  
        if (unlikely(unlink(fname) == 0)) {
            T("infomsg: File deleted: %s", fname);
        } else {
            T("errmsg: %s", strerror(errno));
            RInt(ND_ERR);
        }
    } else {
        T("infomsg: File does not exist: %s", fname);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Check if the directory is writable
 * @param fpath
 *  File path pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int check_directory_writable(const char *fpath) {

    TC("Called { %s(%p)", __func__, fpath);

    if (unlikely((access(fpath, W_OK)) != 0)) {
        T("errmsg: %s", strerror(errno));
        RInt(ND_ERR);
    }

    T("infomsg: directory is writable %s", fpath);

    RInt(ND_OK);
}


/**
 * @brief 
 *  Check if the directory is readable
 * @param fpath
 *  File path pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int check_directory_readable(const char *fpath) {

    TC("Called { %s(%p)", __func__, fpath);

    if (unlikely((access(fpath, R_OK) != 0))) {
        T("errmsg: %s", strerror(errno));
        RInt(ND_ERR);
    }

    T("infomsg: directory is readable: %s\n", fpath);

    RInt(ND_OK);
}


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
int nd_check_fpath (char * fname) {

    TC("Called { %s(%p)", __func__, fname);

    char fpath[COMM_NAMESIZE];
    strncpy(fpath, fname, sizeof(fpath));

    char * slash = strrchr(fpath, '/');
    if (slash != NULL) { 
        *slash = '\0';
    } 
    else { 
        fpath[0] = '.';
        fpath[1] = '\0';
    }

    if (unlikely((nd_check_directory(fpath)) == ND_ERR)) 
        RInt(ND_ERR);

    if (unlikely((check_and_delete_file(fname)) == ND_ERR))
        RInt(ND_ERR);

    if (unlikely((check_directory_writable(fpath)) == ND_ERR))
        RInt(ND_ERR);

    if (unlikely((check_directory_readable(fpath)) == ND_ERR))
        RInt(ND_ERR);

    RInt(ND_OK);
}


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
    const char * name, void * baseaddr, unsigned int memspace, unsigned int count) {

    TC("Called { %s(%s, %p, %u, %u)", __func__, name, baseaddr, memspace, count);

    if (unlikely((!(POWEROF2(count))))) {
		T("errmsg: POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

    int fd = -1;
	if (unlikely((fd = open(name, O_RDWR |O_CREAT, 0666)) < 0)) {
		T("errmsg: %s", strerror(errno));
		RVoidPtr(NULL);
	}

    if(unlikely(ftruncate(fd, (count * memspace)) == -1)){
		close(fd);
		T("errmsg: %s", strerror(errno));
		RVoidPtr(NULL);
	}

	T("infomsg: align_address(%p) : %p", baseaddr, (align_address((uintptr_t)baseaddr)));

    void * p = mmap((void *)(align_address((uintptr_t)baseaddr)), (count * memspace), 
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd , 0);

	if(unlikely((p == MAP_FAILED))) {
		close(fd);
		T("errmsg: %s", strerror(errno));
		RVoidPtr(NULL);
	}

	if (unlikely((!p))) {
        close(fd);
		T("errmsg: %s", strerror(errno));
		RVoidPtr(NULL);
	}

    close(fd);

    RVoidPtr((p));
}


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
    const char * name, void * baseaddr, unsigned int memspace, unsigned int count) {

    TC("Called { %s(%s, %p, %u, %u)", __func__, name, baseaddr, memspace, count);

    if (unlikely((!(POWEROF2(count))))) {
		T("errmsg: POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

	int fd = -1;
    if (unlikely((fd = open(name, O_RDWR, 0666)) == -1)) {
		T("errmsg: %s", strerror(errno));
		RVoidPtr(NULL);
	}

	T("infomsg: align_address(%p) : %p", baseaddr, (align_address((uintptr_t)baseaddr)));

    void * p = mmap((void *)(align_address((uintptr_t)baseaddr)), (count * memspace), 
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd , 0);

    if(unlikely((p == MAP_FAILED) || (p == NULL))){
        close(fd);
		T("errmsg: %s", strerror(errno));
		RVoidPtr(NULL);
	}

    close(fd);

    RVoidPtr((p));
}


/**
 * @brief 
 *  Use the select function to achieve millisecond delay
 * @param microseconds
 *  Delay in microseconds
 */
void nd_delay_microsecond (unsigned long microseconds) {

    TC("Called { %s(%lu)", __func__, microseconds);

    struct timeval timeout = {0, microseconds};
    
    if (unlikely(((select(0, NULL, NULL, NULL, &timeout)) == -1))) {
        T("errmsg: %s", strerror(errno));
    }

    RInt(ND_OK);
}