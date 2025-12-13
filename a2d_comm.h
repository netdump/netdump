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

#ifndef __A2D_COMM_H__
#define __A2D_COMM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "infonode.h"


/**
 * @brief
 *  specify the number of nodes
 */
#define A2D_INFONODE_NUMBER                             (64U)

/**
 * @brief
 *  defines the maximum value of the nodes that can be placed in the display DLL each time
 */
#define A2D_PUTIN_DISPLAY_DLL_MAX_NUMS                  (6U)

typedef struct a2d_info_s
{
    // win3 显示内容链表头 (infonode_t)
    nd_dll_t *w3_displayed_list_head;
    // win3 显示内容链表尾 (infonode_t)
    nd_dll_t *w3_displayed_list_tail;
    // win3 当前选中的节点 (infonode_t)
    nd_dll_t *w3_displayed_cur_node;
    // win3 可用于显示内容的最大行数
    unsigned short w3_displayed_max_lines;
    // win3 当前选中的节点的索引
    unsigned short w3_displayed_cur_index;
    // win3 当前链表中节点的数量
    unsigned short w3_displayed_cur_node_nums;

    // 解析完成的节点数量（解析进程中使用）
    unsigned short analysis_finished_node_nums;
    // 解析完成的链表头（解析进程中使用）
    nd_dll_t *analysis_finished_list_head;
    // 解析完成的链表尾（解析进程中使用）
    nd_dll_t *analysis_finished_list_tail;

    // l1l2node_t 类型节点的空闲链表，用于 win4
    nd_dll_t *l1l2_node_idle_list;
    // infonode_t 类型节点的空闲链表
    nd_dll_t *info_node_idle_list;

    // win4 显示内容链表头 (l1l2node_t)
    l1l2_node_t *w4_l1l2_node_list_head;
    // win4 显示内容链表尾 (l1l2node_t)
    l1l2_node_t *w4_l1l2_node_list_tail;
    // win4 当前选中的节点 (l1l2node_t)
    l1l2_node_t *w4_l1l2_node_cur_node;
    // win4 当前选中的节点的行号
    unsigned short w4_l1l2_node_cur_line;

    // win5 当前选中的行号
    unsigned short w5_displayed_cur_line_number;
    // win5 当前内容的开始索引
    unsigned short w5_displayed_start_byte_index; // from 0 start
    // win5 当前内容的结束索引
    unsigned short w5_displayed_end_byte_index;

    // w5_node_t 类型节点的空闲链表，用于 win5
    nd_dll_t *w5_node_idle_list;
    // win5 显示内容链表头 (w5_ndoe_t)
    w5_node_t *w5_displayed_list_head;
    // win5 当前选中的节点 (w5_ndoe_t)
    w5_node_t *w5_displayed_cur_node;
    // win5 显示内容链表尾 (w5_ndoe_t)
    w5_node_t *w5_displayed_list_tail;

    // 自动和手动的状态标志位
    // Non-manual (ie automatic), the software automatically downloads
    #define A2D_NON_MANUAL                      0x00
    #define A2D_MANUAL                          0x01
    // Manual mode and display the previous line of the current first line
    #define A2D_MANUAL_TOP                      0x02
    // Manual mode and display the next line of the current last line
    #define A2D_MANUAL_BOTTOM                   0x03
    volatile unsigned char is_manual_flag;
    // 解析状态
    // Indicates that data is being parsed
    #define A2D_ANALYSISING                     0x00
    // Indicates that data parsing has been completed
    #define A2D_ALALYSISED                      0x01
    volatile unsigned char analysis_status_flag;
    // 显示状态
    // Representatives are demonstrating the interface
    #define A2D_DISPLAYING                      0x00
    // The representative interface display has been completed
    #define A2D_DISPLAYED                       0x01
    volatile unsigned char displayed_status_flag;

    volatile unsigned char padding[5];
} a2d_info_t;

/**
 * @brief
 *  a2d global information interaction pointer
 */
extern NETDUMP_SHARED a2d_info_t a2d_info;

/**
 * @brief
 *  reset flag 
 */
#define a2d_reset_a2dinfo_flag()                                                            \
    do {                                                                                    \
        a2d_info.displayed_status_flag = A2D_DISPLAYED;                                     \
        a2d_info.analysis_status_flag = A2D_ALALYSISED;                                     \
        a2d_info.is_manual_flag = A2D_NON_MANUAL;                                           \
    } while (0);


/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int a2d_comm_startup(void);

#endif // __A2D_COMM_H_