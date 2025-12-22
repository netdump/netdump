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

#include "c2a_comm.h"
#include "trace.h"

NETDUMP_SHARED ALIGN_CACHELINE unsigned int capture_notify_analysis;

// If each block is 512MB, then the maximum size of the corresponding mapped file is 128GB.
NETDUMP_SHARED ALIGN_PAGE c2a_memory_block_meta_t c2a_mem_block_management[C2A_MAX_BLOCK_NUMS];

/**
 * @brief 
 *  Global ctoa shared memory pointer variable
 */
void * c2a_shm_addr = NULL;


/**
 * @brief 
 *  Global ctoa shared memory, Capture process write data pointer
 */
void * c2a_shm_write_addr = NULL;


/**
 * @brief 
 *  Global ctoa shared memory, Capture process read data pointer
 */
void * c2a_shm_read_addr = NULL;


/**
 * @brief 
 *  Allocate ctoa shared memory
 */
int c2a_comm_init_c2a_comm (void) 
{

    TC("Called { %s(void)", __func__);

    c2a_shm_addr = nd_called_shmopen_mmap_openup_memory(C2A_COMM_SHM_FILENAME,
                                    C2A_COMM_SHM_BASEADDR, C2A_COMM_SHM_FILESIZE);

    TC("C2A_COMM_SHM_FILESIZE: %u", C2A_COMM_SHM_FILESIZE);

    if (unlikely((!c2a_shm_addr)))
    {
        TE("Failed to allocate ctoa memory");
        RInt(ND_ERR);
    }

    memset(c2a_shm_addr, 0, C2A_COMM_SHM_FILESIZE);

    TI("C2A_COMM_SHM_BASEADDR: %p; c2a_shm_addr: %p", C2A_COMM_SHM_BASEADDR, c2a_shm_addr);

    c2a_shm_write_addr = c2a_shm_addr;
    c2a_shm_read_addr = c2a_shm_addr;

    RInt(ND_OK);
}

/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int c2a_comm_startup (void) 
{
    TC("Called { %s(void)", __func__);

    if (unlikely((c2a_comm_init_c2a_comm() == ND_ERR)))
    {
        RInt(ND_ERR);
    }

    TI("__alignof__(struct datastore_s): %lu", __alignof__(struct datastore_s));

    RInt(ND_OK);
}


/**
 * @brief
 *  Inter-process communication resource destruction operation
 */
void c2a_comm_ending (void) 
{

    TC("Called { %s()", __func__);

    munmap(C2A_COMM_SHM_BASEADDR, C2A_COMM_SHM_FILESIZE);

    shm_unlink(C2A_COMM_SHM_FILENAME);

    RVoid();
}

/** Used to detect whether the file size has been modified when initializing a memory block. */
static off_t memory_mmaped_file_size = 0;

#if 0
/**
 * @brief initialization mem_block_management
 */
void c2a_comm_mem_block_management_init(void) {

    TC("Called { %s()", __func__);

    TI("sizeof(c2a_mem_block_management): %ld", sizeof(c2a_mem_block_management));

    memset(c2a_mem_block_management, 0, sizeof(c2a_mem_block_management));

    comm_lock_object_pages(c2a_mem_block_management, sizeof(c2a_mem_block_management));

    RVoid();
}

/** The file descriptor (fd) after the memory mapping process is resolved. */
static int block_0_fd = -1;
/** The file descriptor (fd) of the captured process after memory mapping. */
static int block_1_2_fd = -1;
/** storage resolution process memory mapping offset step */
static int block_0_next_stride = 0;
/** storage capture process memory mapping offset step */
static int block_1_2_next_stride = 0;

/**
 * @brief block0 used for initializing the parsing process
 * @return return file descriptor
 */
int c2a_comm_block_0_init(void) {

    TC("Called { %s()", __func__);

    if (access(C2A_COMM_SHM_STORE_ABSOLUTE_FN, F_OK) != 0) {
        printf("\n\n\tThe BLOCK 0 mapping file does not exist.\n\n");
        TE("The BLOCK 0 mapping file does not exist.");
        abort();
    }

    int fd = -1;
    if (unlikely((fd = open(C2A_COMM_SHM_STORE_ABSOLUTE_FN, O_RDWR, 0666)) < 0)) {
        printf("\n\n\tFailed to open the mapped file;\n\terrmsg: %s\n\n", strerror(errno));
        TE("Failed to open the mapped file;errmsg: %s", strerror(errno));
        abort();
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        printf("\n\n\tFailed to retrieve file information;\n\terrmsg: %s\n\n", strerror(errno));
        TE("Failed to retrieve file information;errmsg: %s", strerror(errno));
        close(fd);
        abort();
    }

    if (st.st_size != memory_mmaped_file_size) {
        printf("\n\n\tThe memory-mapped file was tampered with.\n\n");
        TE("The memory-mapped file was tampered with.");
        close(fd);
        abort();
    }

    void *p = mmap(C2A_COMM_MEM_BLOCK_0_BASE_ADDR, C2A_COMM_MEM_BLOCK_ZONE_SIZE,
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
                   block_0_next_stride * C2A_COMM_MEM_BLOCK_ZONE_SIZE
                );

    if (unlikely((p == MAP_FAILED)) || unlikely((!p))) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        close(fd);
        abort();
    }

    if (p != C2A_COMM_MEM_BLOCK_0_BASE_ADDR) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        close(fd);
        abort();
    }

    memset((char *)p, 0, C2A_COMM_MEM_BLOCK_ZONE_SIZE);

    block_0_fd = fd;
    block_0_next_stride++;

    RInt(fd);
}

/**
 * @brief Blocks 1 and 2 used to initialize the capture process
 * @return return file descriptor
 */
int c2a_comm_block_1_block_2_init(void) {

    TC("Called { %s()", __func__);

    if (access(C2A_COMM_SHM_STORE_ABSOLUTE_FN, F_OK) != 0)
    {
        printf("\n\nThe BLOCK 1 or BLOCK 2 mapping file does not exist.\n\n");
        TE("The BLOCK 1 or BLOCK 2 mapping file does not exist.");
        RInt(ND_ERR);
    }

    int fd = -1;
    if (unlikely((fd = open(C2A_COMM_SHM_STORE_ABSOLUTE_FN, O_RDWR, 0666)) < 0)) {
        printf("\n\n\tFailed to open the mapped file;\n\terrmsg: %s\n\n", strerror(errno));
        TE("Failed to open the mapped file;errmsg: %s", strerror(errno));
        RInt(ND_ERR);
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        printf("\n\n\tFailed to retrieve file information;\n\terrmsg: %s\n\n", strerror(errno));
        TE("Failed to retrieve file information;errmsg: %s", strerror(errno));
        close(fd);
        RInt(ND_ERR);
    }

    if (st.st_size != memory_mmaped_file_size) {
        printf("\n\n\tThe memory-mapped file was tampered with.\n\n");
        TE("The memory-mapped file was tampered with.");
        close(fd);
        RInt(ND_ERR);
    }

    void *p1 = mmap(C2A_COMM_MEM_BLOCK_1_BASE_ADDR, C2A_COMM_MEM_BLOCK_ZONE_SIZE,
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 
                   block_1_2_next_stride * C2A_COMM_MEM_BLOCK_ZONE_SIZE
                );

    if (unlikely((p1 == MAP_FAILED)) || unlikely((!p1))) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        close(fd);
        RInt(ND_ERR);
    }

    if (p1 != C2A_COMM_MEM_BLOCK_1_BASE_ADDR) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        close(fd);
        RInt(ND_ERR);
    }

    memset((char *)p1, 0, C2A_COMM_MEM_BLOCK_ZONE_SIZE);

    c2a_comm_mem_block_t *block1 = (c2a_comm_mem_block_t *)p1;

    block1->crtl.next_idx = 0;
    block1->crtl.remain_zone = C2A_COMM_MEM_BLOCK_ZONE_SIZE - OFFSET_TABLE_SIZE - CTRL_SIZE;
    block1->crtl.block_meta_idx = 0;
    block1->crtl.offset = block_1_2_next_stride *C2A_COMM_MEM_BLOCK_ZONE_SIZE;
    __atomic_store_n(&(block1->crtl.isfull), 0x0, __ATOMIC_SEQ_CST);

    block_1_2_next_stride++;

    void *p2 = mmap(C2A_COMM_MEM_BLOCK_2_BASE_ADDR, C2A_COMM_MEM_BLOCK_ZONE_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 
            block_1_2_next_stride * C2A_COMM_MEM_BLOCK_ZONE_SIZE
        );

    if (unlikely((p2 == MAP_FAILED)) || unlikely((!p2))) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        munmap(C2A_COMM_MEM_BLOCK_1_BASE_ADDR, C2A_COMM_MEM_BLOCK_ZONE_SIZE);
        close(fd);
        RInt(ND_ERR);
    }

    if (p2 != C2A_COMM_MEM_BLOCK_2_BASE_ADDR) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        munmap(C2A_COMM_MEM_BLOCK_1_BASE_ADDR, C2A_COMM_MEM_BLOCK_ZONE_SIZE);
        close(fd);
        RInt(ND_ERR);
    }

    memset((char *)p2, 0, C2A_COMM_MEM_BLOCK_ZONE_SIZE);

    c2a_comm_mem_block_t *block2 = (c2a_comm_mem_block_t *)p2;

    block2->crtl.next_idx = 0;
    block2->crtl.remain_zone = C2A_COMM_MEM_BLOCK_ZONE_SIZE - OFFSET_TABLE_SIZE - CTRL_SIZE;
    block2->crtl.block_meta_idx = 1;
    block2->crtl.offset = block_1_2_next_stride * C2A_COMM_MEM_BLOCK_ZONE_SIZE;
    __atomic_store_n(&(block2->crtl.isfull), 0x0, __ATOMIC_SEQ_CST);

    block_1_2_fd = fd;
    block_1_2_next_stride++;

    RInt(fd);
}

void c2a_comm_block_1_block_2_update_mmap(void *addr, uint32_t block_meta_idx)
{
    TC("Called { %s()", __func__);

    if (munmap(addr, C2A_COMM_MEM_BLOCK_ZONE_SIZE)) {
        printf("\n\n\tFile munmapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File munmapping failed; errmsg: %s", strerror(errno));
        close(block_1_2_fd);
        abort();
    }

    void *p = mmap(addr, C2A_COMM_MEM_BLOCK_ZONE_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, block_1_2_fd, 
            block_1_2_next_stride * C2A_COMM_MEM_BLOCK_ZONE_SIZE
        );

    if (unlikely((p == MAP_FAILED)) || unlikely((!p))) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        close(block_1_2_fd);
        abort();
    }

    if (p != addr) {
        printf("\n\n\tFile mapping failed; errmsg: %s\n\n", strerror(errno));
        TE("File mapping failed; errmsg: %s", strerror(errno));
        close(block_1_2_fd);
        abort();
    }

    memset((char *)p, 0, C2A_COMM_MEM_BLOCK_ZONE_SIZE);

    c2a_comm_mem_block_t *block = (c2a_comm_mem_block_t *)p;

    block->crtl.next_idx = 0;
    block->crtl.remain_zone = C2A_COMM_MEM_BLOCK_ZONE_SIZE - OFFSET_TABLE_SIZE - CTRL_SIZE;
    block->crtl.block_meta_idx = block_meta_idx + 2;
    block->crtl.offset = block_1_2_next_stride * C2A_COMM_MEM_BLOCK_ZONE_SIZE;
    __atomic_store_n(&(block->crtl.isfull), 0x0, __ATOMIC_SEQ_CST);

    block_1_2_next_stride++;

    RVoid();
}
#endif
/**
 * @brief
 *  Load the mapped memory into the memory page
 */
void c2a_comm_memory_load(void) 
{
    TC("Called { %s()", __func__);

    memset(C2A_COMM_SHM_BASEADDR, 0, C2A_COMM_SHM_FILESIZE);

    RVoid();
}

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
int c2a_check_fs_vfs_sparse(void) {

    TC("Called { %s()", __func__);

    if ((nd_check_fpath(C2A_COMM_SHM_STORE_ABSOLUTE_FN)) == ND_ERR) {
        printf("\n\nerrmsg: %s.\n\n", strerror(errno));
        TE("errmsg: %s.", strerror(errno));
        RInt(ND_ERR);
    }

    struct statfs s;
    if ((statfs(C2A_COMM_SHM_STORE_FILE_PATH, &s)) == -1) {
        printf("\n\nerrmsg: %s.\n\n", strerror(errno));
        TE("errmsg: %s.", strerror(errno));
        RInt(ND_ERR);
    }

    switch (s.f_type) {
        case EXT4_SUPER_MAGIC:
        case XFS_SUPER_MAGIC:
            break;
        default:
            printf(
                "\n\n\terrmsg: The file system does not meet the requirements.\n\n"
                "\t Please use the ext4 or xfs file system. \n\n"
            );
            TE("The file system does not meet the requirements; Please use the ext4 or xfs file system.");
            RInt(ND_ERR);
    }

    struct statvfs v;
    if ((statvfs(C2A_COMM_SHM_STORE_FILE_PATH, &v)) == -1) {
        printf("\n\nerrmsg: %s.\n\n", strerror(errno));
        TE("errmsg: %s.", strerror(errno));
        RInt(ND_ERR);
    }

    uint64_t free_bytes = v.f_bavail * v.f_frsize;

    uint32_t free_gbytes = free_bytes >> GiB_SHIFT;

    if (free_gbytes < C2A_COMM_SHM_STORE_FILE_MIN_SIZE) {
        printf("\n\n\terrmsg: Insufficient disk resources.\n\n");
        TE("errmsg: Insufficient disk resources.");
        RInt(ND_ERR);
    }

    uint64_t half = free_gbytes >> 1;

    uint64_t result = 1;
    while (result < half) {
        result <<= 1;
    }

    if (result > C2A_COMM_SHM_STORE_FILE_MAX_SIZE) 
        result = C2A_COMM_SHM_STORE_FILE_MAX_SIZE;

    int fd = -1;
    if (unlikely((fd = open(C2A_COMM_SHM_STORE_ABSOLUTE_FN, O_RDWR | O_CREAT, 0666)) < 0)) {
        printf("\n\nerrmsg: %s.\n\n", strerror(errno));
        TE("errmsg: %s.", strerror(errno));
        RInt(ND_ERR);
    }

    off_t size = result << GiB_SHIFT;
    if ((ftruncate(fd, size)) == -1) {
        printf("\n\nerrmsg: %s.\n\n", strerror(errno));
        TE("errmsg: %s.", strerror(errno));
        RInt(ND_ERR);
    }

    struct stat st;
    if ((fstat(fd, &st)) == -1) {
        printf("\n\nerrmsg: %s.\n\n", strerror(errno));
        TE("errmsg: %s.", strerror(errno));
        RInt(ND_ERR);
    }

    if (st.st_blocks * 512 > 1 << 20) {
        printf("\n\n\terrmsg: The created file is not a sparse file.\n\n");
        TE("errmsg: The created file is not a sparse file.");
        RInt(ND_ERR);
    }

    memory_mmaped_file_size = size;

    RInt(ND_OK);
}

/**
 * @brief initialization mem_block_management
 */
void c2a_comm_mem_block_management_init(void)
{

    TC("Called { %s()", __func__);

    TI("sizeof(c2a_mem_block_management): %ld", sizeof(c2a_mem_block_management));

    memset(c2a_mem_block_management, 0, sizeof(c2a_mem_block_management));

    comm_lock_object_pages(c2a_mem_block_management, sizeof(c2a_mem_block_management));

    

    RVoid();
}

/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int c2a_comm_startup_replace(void)
{
    TC("Called { %s()", __func__);



    RInt(ND_OK);
}

/**
 * @brief
 *  Inter-process communication resource destruction operation
 */
void c2a_comm_ending_replace(void)
{
    TC("Called { %s()", __func__);



    RInt(ND_OK);
}