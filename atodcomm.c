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

#include "atodcomm.h"
#include "trace.h"
#include "infonode.h"


/**
 * @brief 
 *  Global atod shared memory pointer variable
 */
void * G_atod_shm_mem = NULL;


/**
 * @brief
 *  DTOA global information interaction pointer
 */
dtoainfo_t * G_dtoainfo = NULL;


/**
 * @brief
 *  initialize the information node list
 */
int atodcomm_init_infonode_list (void)
{

    TC("Called { %s (void)", __func__);

    infonode_t * tmp = (infonode_t *)(G_atod_shm_mem + sizeof(dtoainfo_t));

    G_dtoainfo->idlelist = &(tmp->listnode);

    int i = 0;
    for (i = 0; i < INFONODE_NUMBER; i++)
    {
        if (i == 0) 
            tmp->listnode.prev = NULL;
        else
            tmp->listnode.prev = (void *)(tmp - 1);

        if (i == (INFONODE_NUMBER - 1))
            tmp->listnode.next = NULL;
        else
            tmp->listnode.next = (void *)(tmp + 1);

        tmp = tmp + 1;
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  initialize the l1l2node list
 */
int atodcomm_init_l1l2node_list (void)
{

    TC("Called { %s (void)", __func__);

    l1l2_node_t * tmp = (l1l2_node_t *)(G_atod_shm_mem + DTOAIFO_T_USE_SIZE + ALL_INFONODE_T_USE_SIZE);

    G_dtoainfo->l1l2idle = &(tmp->l1l2node);

    int i = 0, nums = (INFONODE_NUMBER) * (l1l2_NODE_NUMS);
    for (i = 0; i < nums; i++)
    {
        if (i == 0) 
            tmp->l1l2node.prev = NULL;
        else
            tmp->l1l2node.prev = (void *)(tmp - 1);

        if (i == (nums - 1))
            tmp->l1l2node.next = NULL;
        else
            tmp->l1l2node.next = (void *)(tmp + 1);

        tmp = tmp + 1;
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  Open up shared memory for ATOD
 */
int atodcomm_init_atodcomm(void)
{

    TC("Called { %s(void)", __func__);

    G_atod_shm_mem = nd_called_shmopen_mmap_openup_memory(
        ATODCOMM_SHM_FILENAME, ATODCOMM_SHM_BASEADDR, ATODCOMM_SHM_FILESIZE);

    if (unlikely((!G_atod_shm_mem)))
    {
        TE("Failed to allocate atod memory");
        RInt(ND_ERR);
    }

    memset(ATODCOMM_SHM_BASEADDR, 0, ATODCOMM_SHM_FILESIZE);

    G_dtoainfo = (dtoainfo_t *)G_atod_shm_mem;

    atodcomm_init_dtoainfo_to_zero();

    ATOD_DISPLAY_MAX_LINES = 0;

    atodcomm_init_infonode_list();
    atodcomm_init_l1l2node_list();

    TI("ATODCOMM_SHM_BASEADDR: %p; G_atod_shm_mem: %p", ATODCOMM_SHM_BASEADDR, G_atod_shm_mem);

    RInt(ND_OK);
}


/**
 * @brief
 *  Initialize G_dtoainfo to zero value
 */
void atodcomm_init_dtoainfo_to_zero(void) 
{

    TC("Called { %s(void)", __func__);

    G_dtoainfo->listhead = NULL;
    G_dtoainfo->listtail = NULL;
    G_dtoainfo->curline = NULL;
    G_dtoainfo->idlelist = NULL;
    G_dtoainfo->finlisthead = NULL;
    G_dtoainfo->finlisttail = NULL;

    G_dtoainfo->l1l2idle = NULL;

    G_dtoainfo->curindex = 0;
    G_dtoainfo->curlines = 0;
    G_dtoainfo->finlines = 0;

    memset((void *)G_dtoainfo->flag, 0, sizeof(G_dtoainfo->flag));

    RVoid();
}


/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int atodcomm_startup(void)
{

    TC("Called { %s(void)", __func__);

    if (unlikely((atodcomm_init_atodcomm() == ND_ERR)))
    {
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  Inter-process communication resource destruction operation
 */
void atodcomm_ending(void)
{

    TC("Called { %s()", __func__);

    munmap(ATODCOMM_SHM_BASEADDR, ATODCOMM_SHM_FILESIZE);

    shm_unlink(ATODCOMM_SHM_FILENAME);

    RVoid();
}
