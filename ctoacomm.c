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

#include "ctoacomm.h"
#include "trace.h"


/**
 * @brief Global ctoa shared memory pointer variable
 */
void * G_ctoa_shm_mem = NULL;


/**
 * @brief Global ctoa shared memory, Capture process write data pointer
 */
void * G_ctoa_shm_mem_wp = NULL;


/**
 * @brief Global ctoa shared memory, Capture process read data pointer
 */
void * G_ctoa_shm_mem_rp = NULL;


/**
 * @brief Allocate ctoa shared memory
 */
int ctoacomm_init_ctoacomm (void) 
{

    TC("Called { %s(void)", __func__);

    G_ctoa_shm_mem = nd_called_shmopen_mmap_openup_memory(CTOACOMM_SHM_FILENAME,
                                    CTOACOMM_SHM_BASEADDR, CTOACOMM_SHM_FILESIZE);

    if (unlikely((!G_ctoa_shm_mem)))
    {
        TE("Failed to allocate ctoa memory");
        RInt(ND_ERR);
    }

    //memset(G_ctoa_shm_mem, 0, CTOACOMM_SHM_FILESIZE);

    TI("CTOACOMM_SHM_BASEADDR: %p; G_ctoa_shm_mem: %p", CTOACOMM_SHM_BASEADDR, G_ctoa_shm_mem);

    G_ctoa_shm_mem_wp = G_ctoa_shm_mem;
    G_ctoa_shm_mem_rp = G_ctoa_shm_mem;

    RInt(ND_OK);
}


/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int ctoacomm_startup (void) 
{

    TC("Called { %s(void)", __func__);

    if (unlikely((ctoacomm_init_ctoacomm() == ND_ERR)))
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
void ctoacomm_ending (void) 
{

    TC("Called { %s()", __func__);

    munmap(CTOACOMM_SHM_BASEADDR, CTOACOMM_SHM_FILESIZE);

    shm_unlink(CTOACOMM_SHM_FILENAME);

    RVoid();
}


/**
 * @brief
 *  Load the mapped memory into the memory page
 */
void ctoacomm_memory_load(void) 
{
    TC("Called { %s()", __func__);

    memset(CTOACOMM_SHM_BASEADDR, 0, CTOACOMM_SHM_FILESIZE);

    RVoid();
}



