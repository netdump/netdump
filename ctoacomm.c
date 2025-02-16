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
 * @brief Global ctoa shared memory cursor
 */
void * G_ctos_shm_mem_cursor = NULL;


/**
 * @brief Allocate ctoa shared memory
 */
int ctoacomm_init_ctoacomm (void) 
{

    TC("Called { %s(void)", __func__);

    void * G_ctoa_shm_mem = nd_called_open_mmap_openup_memory(CTOACOMM_SHM_FULLNAME, 
                        CTOACOMM_SHM_BASEADDR, CTOACOMM_SHM_FILESIZE, 1);

    if (unlikely((!G_ctoa_shm_mem)))
    {
        TE("Failed to allocate ctoa memory");
        RInt(ND_ERR);
    }

    G_ctos_shm_mem_cursor = G_ctoa_shm_mem;

    RInt(ND_OK);
}


/**
 * @brief 
 *  
 */
int ctoacomm_startup (void) 
{

    TC("Called { %s(void)", __func__);




    RInt(ND_OK);
}
