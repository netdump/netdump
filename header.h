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

#ifndef __HEADER_H__
#define __HEADER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include "pcap.h"
#include "trace.h"
#include "ndo.h"
#include "infonode.h"
#include "atodcomm.h"
#include "common.h"

#if 1
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;
#endif

/*
 * Check whether this is GCC major.minor or a later release, or some
 * compiler that claims to be "just like GCC" of that version or a
 * later release.
 */

#if !defined(__GNUC__)
/* Not GCC and not "just like GCC" */
#define ND_IS_AT_LEAST_GNUC_VERSION(major, minor) 0
#else
/* GCC or "just like GCC" */
#define ND_IS_AT_LEAST_GNUC_VERSION(major, minor) \
    (__GNUC__ > (major) ||                        \
     (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#endif

#if __has_attribute(unused) || ND_IS_AT_LEAST_GNUC_VERSION(2, 0)
/*
 * Compiler with support for __attribute__((unused)), or GCC 2.0 and
 * later, so it supports __attribute__((unused)).
 */
#define _U_ __attribute__((unused))
#else
/*
 * We don't know of any way to mark a variable as unused.
 */
#define _U_
#endif

#if 0
/**
 * @brief
 *  get l1l2node and fill l1l2node and put l1l2node
 * @param ifn ifnonode_t pointer
 * @param isexpand l1l2node member
 * @param byte_start l1l2node member
 * @param byte_end l1l2node member
 * @param format content format
 * @param content content
 * @return l1l2node pointer
 */
static l1l2_node_t * nd_get_fill_put_l1l2_node_level1(
    infonode_t *ifn, int isexpand, int byte_start, int byte_end, const char * format, ...)
{
    if (!ifn || isexpand < 0 || isexpand > 1 || !format || 
        byte_start < 0 || byte_start > INFONODE_BYTE_START_MAX || 
        byte_end < 0 || byte_end > INFONODE_BYTE_START_MAX)
    {
        TE("fatal param error; ifn: %p, isexpand: %d, byte_start: %d, byte_end: %d, format: %p",
           ifn, isexpand, byte_start, byte_end, format);
           exit(1);
    }

    nd_dll_t * node = nd_dll_takeout_from_head_s(&ATOD_L1L2IDLE_DLL);
    if (!node)
    {
        TE("fatal logic error; node: %p; ATOD_L1L2IDLE_DLL: %p", node, ATOD_L1L2IDLE_DLL);
        exit(1);
    }

    l1l2_node_t * l1l2 = container_of(node, l1l2_node_t, l1l2node);
    l1l2->superior = NULL;
    l1l2->level = 1;
    l1l2->isexpand = isexpand;
    l1l2->byte_start = byte_start;
    l1l2->byte_end = byte_end;
    memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
    va_list args;
    va_start(args, format);
    vsnprintf(l1l2->content, L1L2NODE_CONTENT_LENGTH, format, args);
    va_end(args);
    nd_dll_insert_into_tail(&(ifn->l1head), &(ifn->l1tail), &(l1l2->l1node));
    nd_dll_insert_into_tail(&(ifn->l1l2head), &(ifn->l1l2tail), &(l1l2->l1l2node));

    return l1l2;
}

/**
 * @brief
 *  get l1l2node and fill l1l2node and put l1l2node
 * @param ifn ifnonode_t pointer
 * @param su l1l2node member
 * @param isexpand l1l2node member
 * @param byte_start l1l2node member
 * @param byte_end l1l2node member
 * @param format content format
 * @param content content
 * @return void
 */
static void nd_get_fill_put_l1l2_node_level2(
    infonode_t *ifn, l1l2_node_t *su, int isexpand, int byte_start, int byte_end, const char *format, ...)
{
    if (!ifn || !su || isexpand < 0 || isexpand > 1 || !format ||
        byte_start < 0 || byte_start > INFONODE_BYTE_START_MAX ||
        byte_end < 0 || byte_end > INFONODE_BYTE_START_MAX)
    {
        TE("fatal param error; ifn: %p, su: %p, isexpand: %d, byte_start: %d, byte_end: %d, format: %p",
           ifn, su, isexpand, byte_start, byte_end, format);
        exit(1);
    }

    nd_dll_t *node = nd_dll_takeout_from_head_s(&ATOD_L1L2IDLE_DLL);
    if (!node)
    {
        TE("fatal logic error; node: %p; ATOD_L1L2IDLE_DLL: %p", node, ATOD_L1L2IDLE_DLL);
        exit(1);
    }

    l1l2_node_t *l1l2 = container_of(node, l1l2_node_t, l1l2node);
    l1l2->superior = su;
    l1l2->level = 2;
    l1l2->isexpand = isexpand;
    l1l2->byte_start = byte_start;
    l1l2->byte_end = byte_end;
    memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
    va_list args;
    va_start(args, format);
    vsnprintf(l1l2->content, L1L2NODE_CONTENT_LENGTH, format, args);
    va_end(args);
    nd_dll_insert_into_tail(&(ifn->l1l2head), &(ifn->l1l2tail), &(l1l2->l1l2node));

    return ;
}
#endif

/**
 * @brief
 *  get l1l2node and fill l1l2node and put l1l2node
 * @param ifn ifnonode_t pointer
 * @param isexpand l1l2node member
 * @param format content format
 * @return l1l2node pointer
 */
static l1l2_node_t *nd_filling_l1(infonode_t *ifn, int isexpand, const char *format, ...)
{
    if (!ifn || isexpand < 0 || isexpand > 1 || !format)
    {
        TE("fatal param error; ifn: %p, isexpand: %d, format: %p", ifn, isexpand, format);
        exit(1);
    }

    nd_dll_t *node = nd_dll_takeout_from_head_s(&ATOD_L1L2IDLE_DLL);
    if (!node)
    {
        TE("fatal logic error; node: %p; ATOD_L1L2IDLE_DLL: %p", node, ATOD_L1L2IDLE_DLL);
        exit(1);
    }

    l1l2_node_t *l1l2 = container_of(node, l1l2_node_t, l1l2node);
    l1l2->superior = NULL;
    l1l2->level = 1;
    l1l2->isexpand = isexpand;
    l1l2->byte_start = 0;
    l1l2->byte_end = 0;

    memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
    va_list args;
    va_start(args, format);
    vsnprintf(l1l2->content, L1L2NODE_CONTENT_LENGTH, format, args);
    va_end(args);
    nd_dll_insert_into_tail(&(ifn->l1head), &(ifn->l1tail), &(l1l2->l1node));
    nd_dll_insert_into_tail(&(ifn->l1l2head), &(ifn->l1l2tail), &(l1l2->l1l2node));

    return l1l2;
}

/**
 * @brief
 *  get l1l2node and fill l1l2node and put l1l2node
 * @param ifn ifnonode_t pointer
 * @param su l1l2node member
 * @param isexpand l1l2node member
 * @param byte_start l1l2node member
 * @param byte_end l1l2node member
 * @param format content format
 * @param content content
 * @return void
 */
static void nd_filling_l2(
    infonode_t *ifn, l1l2_node_t *su, int isexpand, int length, const char *format, ...)
{
    if (!ifn || !su || isexpand < 0 || isexpand > 1 || length < 0 || length > 65535 || !format )
    {
        TE("fatal param error; ifn: %p, su: %p, isexpand: %d, length: %d, format: %p",
           ifn, su, isexpand, length, format);
        exit(1);
    }

    nd_dll_t *node = nd_dll_takeout_from_head_s(&ATOD_L1L2IDLE_DLL);
    if (!node)
    {
        TE("fatal logic error; node: %p; ATOD_L1L2IDLE_DLL: %p", node, ATOD_L1L2IDLE_DLL);
        exit(1);
    }

    l1l2_node_t *l1l2 = container_of(node, l1l2_node_t, l1l2node);
    
    l1l2->superior = su;
    l1l2->level = 2;
    l1l2->isexpand = isexpand;
    l1l2->byte_start = ifn->idx;
    l1l2->byte_end = ifn->idx + length - 1;
    ifn->idx += length;

    memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
    va_list args;
    va_start(args, format);
    vsnprintf(l1l2->content, L1L2NODE_CONTENT_LENGTH, format, args);
    va_end(args);
    nd_dll_insert_into_tail(&(ifn->l1l2head), &(ifn->l1l2tail), &(l1l2->l1l2node));

    return;
}

#endif  // __HEADER_H__