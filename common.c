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

#include <time.h>
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
	TC("Called { %s(%p)", __func__, (void*)(addr));

    long page_size = sysconf(_SC_PAGESIZE); 

    if (unlikely(page_size == -1)) {
		TE("%s", strerror(errno));
        page_size = 4096;
	}

    #if 0
    long page_size = (1 << 21);
    #endif

    RULong(((addr + page_size - 1) & ~(page_size - 1)));
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
            TE("%s", strerror(errno));
            RInt(ND_ERR);
        }
        TI("directory created: %s", fpath);
    } else if (S_ISDIR(statbuf.st_mode)) {
        TI("directory exists: %s", fpath);
    } else {
        TI("Path exists but is not a directory: %s", fpath);
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
            TI("File deleted: %s", fname);
        } else {
            TE("%s", strerror(errno));
            RInt(ND_ERR);
        }
    } else {
        TI("File does not exist: %s", fname);
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
        TE("%s", strerror(errno));
        RInt(ND_ERR);
    }

    TI("directory is writable %s", fpath);

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
        TE("%s", strerror(errno));
        RInt(ND_ERR);
    }

    TI("directory is readable: %s", fpath);

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
    snprintf(fpath, sizeof(fpath), "%s", fname);

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
    const char * name, void * baseaddr, unsigned long long memspace, unsigned int count) {

    TC("Called { %s(%s, %p, %llu, %u)", __func__, name, (void *)baseaddr, memspace, count);

    if (unlikely((!(POWEROF2(count))))) {
		TE("POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

    int fd = -1;
	if (unlikely((fd = open(name, O_RDWR |O_CREAT, 0666)) < 0)) {
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

    if(unlikely(ftruncate(fd, (count * memspace)) == -1)){
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	TI("align_address(%p) : %p", (void *)baseaddr, (void *)(align_address((uintptr_t)baseaddr)));

    void *p = mmap((void *)(align_address((uintptr_t)baseaddr)), (count * memspace),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED /*| MAP_POPULATE | MAP_HUGETLB */, fd, 0);

    if(unlikely((p == MAP_FAILED))) {
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	if (unlikely((!p))) {
        close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

    close(fd);

    RVoidPtr((p));
}


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
void *nd_called_shmopen_mmap_openup_memory (const char *name, void *baseaddr, unsigned int memsize)
{

    TC("Called { %s(%s, %p, %u)", __func__, name, (void *)baseaddr, memsize);

    int fd = -1;
    if (unlikely((fd = shm_open(name, O_RDWR | O_CREAT, 0666)) < 0))
    {
        TE("%s", strerror(errno));
        RVoidPtr(NULL);
    }

    if (unlikely(ftruncate(fd, memsize) == -1))
    {
        close(fd);
        TE("%s", strerror(errno));
        RVoidPtr(NULL);
    }

    TI("align_address(%p) : %p", (void *)baseaddr, (void *)(align_address((uintptr_t)baseaddr)));

    void *p = mmap((void *)(align_address((uintptr_t)baseaddr)), memsize,
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED /* | MAP_POPULATE | MAP_HUGETLB */, fd, 0);

    if (unlikely((p == MAP_FAILED)))
    {
        close(fd);
        TE("%s", strerror(errno));
        RVoidPtr(NULL);
    }

    if (unlikely((!p)))
    {
        close(fd);
        TE("%s", strerror(errno));
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
		TE("POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

	int fd = -1;
    if (unlikely((fd = open(name, O_RDWR, 0666)) == -1)) {
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	TI("align_address(%p) : %p", (void *)baseaddr, (void *)(align_address((uintptr_t)baseaddr)));

    void *p = mmap((void *)(align_address((uintptr_t)baseaddr)), (count * memspace),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);

    if(unlikely((p == MAP_FAILED) || (p == NULL))){
        close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

    close(fd);

    RVoidPtr((p));
}


/**
 * @brief
 *  Use the select function to achieve millisecond delay
 * @param sec
 *  Delay in second
 * @param nanoseconds
 *  Delay in nanoseconds
 */
void nd_delay_microsecond(unsigned int sec, unsigned long nanoseconds)
{
    //TC("Called { %s(%u, %lu)", __func__, sec, microseconds);

    #if 0
    struct timeval timeout = {sec, microseconds};
    
    if (unlikely(((select(0, NULL, NULL, NULL, &timeout)) == -1))) {
        TE("%s", strerror(errno));
    }
    #endif

    struct timespec req = {
        .tv_sec = sec,
        .tv_nsec = nanoseconds
    };

    nanosleep(&req, NULL);

    //RVoid();
}


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
size_t strlcpy(char *dst, const char *src, size_t siz)
{
    //TC("Called { %s(%p, %p, %ld)", __func__, dst, src, siz);

    char *d = dst;
    const char *s = src;
    size_t n = siz;

    /* Copy as many bytes as will fit */
    if (n != 0 && --n != 0)
    {
        do
        {
            if ((*d++ = *s++) == 0)
                break;
        } while (--n != 0);
    }

    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0)
    {
        if (siz != 0)
            *d = '\0'; /* NUL-terminate dst */
        while (*s++)
            ;
    }

    return (s - src - 1); /* count does not include NUL */
    //RULong((s - src - 1));
}


/**
 * @brief
 *  Take the node from the head of the doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t * nd_dll_takeout_from_head(nd_dll_t ** head, nd_dll_t ** tail)
{

    //TC("Called { %s(%p, %p)", __func__, head, tail);

    nd_dll_t * tmp = NULL;

    if (!head || !tail) {
        TE("Param is null; head: %p, tail: %p;", head, tail);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    if (!(*head) && !(*tail)) {
        TE("Param is null; *head: %p; *tail: %p", *head, *tail);
        //RVoidPtr(tmp);
        return tmp;
    }

    tmp = *head;

    *head = tmp->next;
    if (*head) 
        (*head)->prev = NULL;
    else
        *tail = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    //RVoidPtr(tmp);
    return tmp;
}


/**
 * @brief
 *  Take the node from the head of the doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t *nd_dll_takeout_from_head_s(nd_dll_t ** head)
{

    //TC("Called { %s(%p)", __func__, head);

    nd_dll_t *tmp = NULL;

    if (!head) {
        TE("Param is null; head: %p", head);
        exit(1);
    }

    if (!(*head)) {
        TE("Param is null; *head: %p", *head);
        //RVoidPtr(tmp);
        return tmp;
    }

    tmp = *head;

    *head = tmp->next;
    if (*head)
        (*head)->prev = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    //RVoidPtr(tmp);
    return tmp;
}


/**
 * @brief
 *  Take the node from the tail of the doubly linked list
 * @memberof tail
 *  the tail of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t * nd_dll_takeout_from_tail(nd_dll_t ** head, nd_dll_t ** tail)
{

    //TC("Called { %s(%p, %p)", __func__, head, tail);

    nd_dll_t * tmp = NULL;

    if (!head || !tail) {
        TE("Param is null; head: %p, tail: %p", head, tail);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    if (!(*tail) && !(*head)) {
        TE("Param is numm; *tail: %p", *tail);
        //RVoidPtr(tmp);
        return tmp;
    }

    tmp = *tail;

    *tail = tmp->prev;
    if (*tail)
        (*tail)->next = NULL;
    else 
        *head = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    //RVoidPtr(tmp);
    return tmp;
}


/**
 * @brief
 *  Insert the head of a doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_intsert_into_head (nd_dll_t ** head, nd_dll_t ** tail, nd_dll_t * node)
{

    //TC("Called { %s(%p, %p, %p)", __func__, head, tail, node);

    if (!head || !tail || !node) {
        TE("Param is null; head: %p; node: %p", head, node);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    nd_dll_t * tmp = *head;

    if (!(*head)) {
        node->next = NULL;
        *tail = node;
    }
    else {
        node->next = tmp;
    }

    node->prev = NULL;

    if (tmp)
        tmp->prev = node;

    *head = node;

    //RInt(ND_OK);
    return ND_OK;
}


/**
 * @brief
 *  Insert the head of a doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_intsert_into_head_s(nd_dll_t ** head, nd_dll_t * node)
{

    //TC("Called { %s(%p, %p)", __func__, head, node);

    if (!head || !node)
    {
        TE("Param is null; head: %p; node: %p", head, node);
        exit(1);
    }

    nd_dll_t *tmp = *head;

    if (!(*head))
        node->next = NULL;
    else
        node->next = tmp;

    node->prev = NULL;

    if (tmp)
        tmp->prev = node;

    *head = node;

    //RInt(ND_OK);
    return ND_OK;
}


/**
 * @brief 
 *  Check if the linked list segment is complete
 */
static void assert_link_valid(nd_dll_t *nodehead, nd_dll_t *nodetail)
{
    nd_dll_t *p = nodehead;
    while (p && p != nodetail)
        p = p->next;
    if (p != nodetail)
    {
        TE("nodehead and nodetail are not in the same list!");
        exit(1);
    }
}


/**
 * @brief
 *  insert the head of a doubly linked list (multiple)
 * @param head
 *  the head of the doubly linked list
 * @param nodehead
 *  list head to be inserted
 * @param nodetail
 *  list tail to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_insert_into_head_multiple (nd_dll_t ** head, nd_dll_t * nodehead, nd_dll_t * nodetail)
{

    //TC("Called { %s(%p, %p, %p)", __func__, head, nodehead, nodetail);

    if (!head || !nodehead || !nodetail) 
    {
        TE("there is a case where the parameter is NULL(head: %p, nodehead: %p, nodetail: %p)",
           head, nodehead, nodetail);
        exit(1);
    }

    assert_link_valid(nodehead, nodetail);

    nd_dll_t * tmp = *head;

    if (!(*head))
        nodetail->next = NULL;
    else
        nodetail->next = tmp;

    nodehead->prev = NULL;

    if (tmp)
        tmp->prev = nodetail;

    *head = nodehead;

    //RInt(ND_OK);
    return ND_OK;
}


/**
 * @brief
 *  Insert the tail of a doubly linked list
 * @memberof tail
 *  the tail of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_insert_into_tail(nd_dll_t ** head, nd_dll_t ** tail, nd_dll_t * node)
{
    //TC("Called { %s(%p, %p, %p)", __func__, head, tail, node);

    if (!head || !tail || !node) {
        TE("Param is null; head: %p, tail: %p; node: %p", head, tail, node);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    nd_dll_t * tmp = *tail;

    if (!(*tail)) {
        node->prev = NULL;
        *head = node;
    }
    else {
        node->prev = tmp;
    }

    node->next = NULL;

    if (tmp)
        tmp->next = node;

    *tail = node;

    //RInt(ND_OK);
    return ND_OK;
}


/**
 * @brief
 *  create shared memory for custom segments for inter-process communication
 */
int comm_zone_startup(void) {

    TC("Called { %s(void)", __func__);

    int fd = shm_open(NETDUMP_FILENAME, O_CREAT | O_RDWR, 0666);

    if (fd < 0) {
        TE("shm_open errmsg: %s", strerror(errno));
        RInt(ND_ERR);
    }

    ftruncate(fd, NETDUMP_ZONESIZE);

    unsigned long size = __netdump_shared_end - __netdump_shared_start;

    void *ptr = mmap(__netdump_shared_start, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);

    if (ptr == MAP_FAILED) {
        TE("mmap errmsg: %s", strerror(errno));
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  inter-process communication resource destruction operation
 */
void comm_zone_ending(void)
{
    TC("Called { %s()", __func__);

    unsigned long size = __netdump_shared_end - __netdump_shared_start;

    munmap(__netdump_shared_start, size);

    shm_unlink(NETDUMP_FILENAME);

    RVoid();
}
