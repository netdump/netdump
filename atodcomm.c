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
 *  Initialize the information node list
 */
int atodcomm_init_infonode_list (void)
{

    TC("Called { %s (void)", __func__);

    infonode_t * tmp = (infonode_t *)(G_atod_shm_mem + sizeof(dtoainfo_t));

    int i = 0;
    for (i = 0; i < INFONODE_NUMBER; i++)
    {
        if (i == 0) 
            tmp->prev = NULL;
        else 
            tmp->prev = tmp - 1;

        if (i == (INFONODE_NUMBER - 1))
            tmp->next = NULL;
        else
            tmp->next = tmp + 1;

        tmp = tmp + 1;
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  Remove a node from a doubly linked list
 * @memberof head
 *  Head of a doubly linked list
 * @return
 *  Returns a node if successful
 *  Returns NULL if failed
 */
infonode_t * atodcomm_takeout_infonode_from_list (infonode_t * head)
{

    TC("Called { %s (%p)", __func__, head);

    infonode_t * tmp = NULL;

    if (!head) 
    {
        TE("The list head is NULL");
        exit(1);
    }

    tmp = head;
    head = tmp->next;
    head->prev = NULL;

    tmp->next = NULL;

    RVoidPtr(tmp);
}


/**
 * @brief
 *  Return the node to the linked list
 * @memberof head
 *  Head of a doubly linked list
 * @memberof node
 *  Nodes to be returned
 * @return
 *  If successful, it returns ND_OK. 
 *  If failed, it returns ND_ERR.
 */
int atodcomm_putin_infonode_to_list (infonode_t * head, infonode_t * node)
{

    TC("Called { %s (%p, %p)", __func__, head, node);

    infonode_t * tmp = NULL;

    if (!head) 
    {
        TE("The list head is NULL");
        exit(1);
    }

    if (!node) 
    {
        TE("The node is NULL");
        exit(1);
    }

    tmp = head;
    head = node;

    head->prev = NULL;
    head->next = tmp;

    tmp->prev = head;

    RInt(ND_OK);
}


/**
 * @brief
 *  Take a node from the display list head
 * @memberof head
 *  Display link header
 * @return
 *  Returns a node if successful
 *  Returns NULL if failed
 */
infonode_t * atodcomm_takeout_infonode_from_display_list_head (infonode_t * head)
{

    TC("Called { %s (%p)", __func__, head);

    infonode_t * tmp = NULL;

    if (!head)
    {
        TE("The list head is NULL");
        exit(1);
    }

    tmp = head;
    head = tmp->next;
    head->prev = NULL;

    tmp->next = NULL;

    RVoidPtr(tmp);
}


/**
 * @brief
 *  Take a node from the display list tail
 * @memberof tail
 *  Display the end of the linked list
 * @return
 *  Returns a node if successful
 *  Returns NULL if failed
 */
infonode_t * atodcomm_takeout_infonode_from_display_list_tail (infonode_t * tail)
{

    TC("Called { %s (%p)", __func__, tail);

    infonode_t * tmp = NULL;

    if (!tail) 
    {
        TE("The list tail is NULL");
        exit(1);
    }

    tmp = tail;
    tail = tmp->prev;
    tail->next = NULL;

    tmp->prev = NULL;

    RVoidPtr(tmp);
}


/**
 * @brief
 *  Insert the node to the end of the display list
 * @memberof tail
 *  Display the end of the linked list
 * @memberof node
 *  Nodes to be returned
 * @return
 *  If successful, it returns ND_OK.
 *  If failed, it returns ND_ERR.
 */
int atod_putin_infonode_to_display_list_tail (infonode_t * tail, infonode_t * node) 
{

    TC("Called { %s (%p, %p)", __func__, tail, node);

    if (!tail) 
    {
        TE("The list tail is NULL");
        exit(1);
    }

    if (!node)
    {
        TE("The node is NULL");
        exit(1);
    }

    tail->next = node;
    node->prev = tail;

    tail = node;

    RInt(ND_OK);
}


/**
 * @brief
 *  Insert the node into the head of the display list
 * @memberof head
 *  Display link header
 * @memberof node
 *  Nodes to be returned
 * @return
 *  If successful, it returns ND_OK.
 *  If failed, it returns ND_ERR.
 */
int atod_putin_infonode_to_display_list_head (infonode_t * head, infonode_t * node) 
{

    TC("Called { %s (%p, %p)", __func__, head, node);

    infonode_t * tmp = NULL;

    if (!head)
    {
        TE("The list head is NULL");
        exit(1);
    }

    if (!node)
    {
        TE("The node is NULL");
        exit(1);
    }

    tmp = head;
    head = node;

    head->prev = NULL;
    head->next = tmp;

    tmp->prev = head;

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
    
    G_dtoainfo->listhead = NULL;
    G_dtoainfo->listtail = NULL;
    G_dtoainfo->curline = NULL;
    G_dtoainfo->idlelist = NULL;
    G_dtoainfo->finlist = NULL;

    G_dtoainfo->nlines = 0;
    G_dtoainfo->curindex = 0;
    G_dtoainfo->curlines = 0;
    G_dtoainfo->finlines = 0;

    memset((void *)G_dtoainfo->flag, 0, sizeof(G_dtoainfo->flag));

    atodcomm_init_infonode_list();

    G_dtoainfo->idlelist = (infonode_t *)(G_atod_shm_mem + sizeof(dtoainfo_t));

    TI("ATODCOMM_SHM_BASEADDR: %p; G_atod_shm_mem: %p", ATODCOMM_SHM_BASEADDR, G_atod_shm_mem);

    RInt(ND_OK);
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
