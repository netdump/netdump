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

netdump_shared_t unsigned int capture_notify_analysis;

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

    TC("C2A_COMM_SHM_FILESIZE: %llu", C2A_COMM_SHM_FILESIZE);

    if (unlikely((!c2a_shm_addr)))
    {
        TE("Failed to allocate ctoa memory");
        RInt(ND_ERR);
    }

    //memset(c2a_shm_addr, 0, C2A_COMM_SHM_FILESIZE);

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



