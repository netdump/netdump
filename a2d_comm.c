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
NETDUMP_SHARED a2d_info_t a2d_info = {0};

/**
 * @brief information node array
 */
NETDUMP_SHARED infonode_t infonode_array[A2D_INFONODE_NUMBER] = {0};

/**
 * @brief level 1 level2 node array
 */
NETDUMP_SHARED l1l2_node_t l1l2node_array[(A2D_INFONODE_NUMBER) * (l1l2_NODE_NUMS)] = {0};

/**
 * @brief window 5 node array
 */
NETDUMP_SHARED w5_node_t w5_node_array[(A2D_INFONODE_NUMBER) * (W5_NODE_NUMS)] = {0};


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
 * @brief reset some members of a2d_info
 */
void a2d_comm_reset_a2d_info_member(void)
{

    TC("Called { %s(void)", __func__);

    a2d_info.w3_displayed_list_head = NULL;
    a2d_info.w3_displayed_list_tail = NULL;
    a2d_info.w3_displayed_cur_node = NULL;
    a2d_info.w3_displayed_cur_index = 0;
    a2d_info.w3_displayed_cur_node_nums = 0;

    a2d_info.analysis_finished_list_head = NULL;
    a2d_info.analysis_finished_list_tail = NULL;
    a2d_info.analysis_finished_node_nums = 0;

    a2d_info.l1l2_node_idle_list = NULL;
    a2d_info.info_node_idle_list = NULL;

    a2d_info.w4_l1l2_node_list_head = NULL;
    a2d_info.w4_l1l2_node_list_tail = NULL;
    a2d_info.w4_l1l2_node_cur_node = NULL;
    a2d_info.w4_l1l2_node_cur_line = 0;

    a2d_info.w5_displayed_cur_line_number = 0;
    a2d_info.w5_displayed_start_byte_index = 0;
    a2d_info.w5_displayed_end_byte_index = 0;

    a2d_info.w5_node_idle_list = NULL;
    a2d_info.w5_displayed_list_head = NULL;
    a2d_info.w5_displayed_cur_node = NULL;
    a2d_info.w5_displayed_list_tail = NULL;

    a2d_info.is_manual_flag = 0;
    a2d_info.analysis_status_flag = 0;
    a2d_info.displayed_status_flag = 0;

    RVoid();
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

    a2d_comm_reset_a2d_info_member();

    memset(infonode_array, 0, A2D_INFONODE_NUMBER * sizeof(infonode_t));

    memset(l1l2node_array, 0, (A2D_INFONODE_NUMBER) * (l1l2_NODE_NUMS) * sizeof(l1l2_node_t));

    memset(w5_node_array, 0, (A2D_INFONODE_NUMBER) * (W5_NODE_NUMS) * sizeof(w5_node_t));

    atodcomm_init_infonode_idle_list();

    atodcomm_init_l1l2node_idle_list();
    
    atodcomm_init_w5node_idle_list();

    RInt(ND_OK);
}

