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

#include "a2d_comm.h"
#include "trace.h"
#include "infonode.h"

/**
 * @brief a2d global information interaction pointer
 */
netdump_shared_t a2d_info_t a2d_info = {0};

/**
 * @brief information node array
 */
netdump_shared_t infonode_t infonode_array[A2D_INFONODE_NUMBER] = {0};

/**
 * @brief level 1 level2 node array
 */
netdump_shared_t l1l2_node_t l1l2node_array[(A2D_INFONODE_NUMBER) * (l1l2_NODE_NUMS)] = {0};

/**
 * @brief window 5 node array
 */
netdump_shared_t w5_node_t w5_node_array[(A2D_INFONODE_NUMBER) * (W5_NODE_NUMS)] = {0};


/**
 * @brief
 *  initialize the information node idle list
 */
int atodcomm_init_infonode_idle_list (void)
{
    TC("Called { %s (void)", __func__);

    infonode_t * tmp = infonode_array;

    a2d_info.info_node_idle_list = &(infonode_array[0].listnode);

    int i = 0;
    for (i = 0; i < A2D_INFONODE_NUMBER; i++)
    {
        if (i == 0) 
            tmp->listnode.prev = NULL;
        else 
            tmp->listnode.prev = (void *)(tmp - 1);

        if (i == (A2D_INFONODE_NUMBER - 1))
            tmp->listnode.next = NULL;
        else
            tmp->listnode.next = (void *)(tmp + 1);

        tmp = tmp + 1;
    }

    RInt(ND_OK);
}

/**
 * @brief
 *  initialize the l1l2node idle list
 */
int atodcomm_init_l1l2node_idle_list (void)
{
    TC("Called { %s (void)", __func__);

    l1l2_node_t *tmp = l1l2node_array;

    a2d_info.l1l2_node_idle_list = &(l1l2node_array[0].l1l2node);

    int i = 0, nums = (A2D_INFONODE_NUMBER) * (l1l2_NODE_NUMS);
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
 *  initialize the w5node list
 */
int atodcomm_init_w5node_idle_list (void)
{
    TC("Called { %s (void)", __func__);

    w5_node_t *tmp = w5_node_array;

    a2d_info.w5_node_idle_list = &(w5_node_array[0].w5node);

    int i, nums = (A2D_INFONODE_NUMBER) * (W5_NODE_NUMS);
    for (i = 0; i < nums; i++)
    {
        if (i == 0)
            tmp->w5node.prev = NULL;
        else
            tmp->w5node.prev = (void *)(tmp - 1);

        if (i == (nums - 1))
            tmp->w5node.next = NULL;
        else
            tmp->w5node.next = (void *)(tmp + 1);

        tmp = tmp + 1;
    }

    RInt(ND_OK);
}

/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int a2d_comm_startup(void)
{

    TC("Called { %s(void)", __func__);

    memset(infonode_array, 0, A2D_INFONODE_NUMBER * sizeof(infonode_t));

    memset(l1l2node_array, 0, (A2D_INFONODE_NUMBER) * (l1l2_NODE_NUMS) * sizeof(l1l2_node_t));

    memset(w5_node_array, 0, (A2D_INFONODE_NUMBER) * (W5_NODE_NUMS) * sizeof(w5_node_t));

    atodcomm_init_infonode_idle_list();

    atodcomm_init_l1l2node_idle_list();
    
    atodcomm_init_w5node_idle_list();

    RInt(ND_OK);
}

