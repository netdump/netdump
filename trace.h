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

#ifndef __TRACE_H__
#define __TRACE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define trace_log(fmt, ...)                                                                                                             \
    do {                                                                                                                                \
        printf("[%s][%s:%d]"fmt, __TIME__, __func__, __LINE__, ##__VA_ARGS__);                                                          \
    } while (0);                                                                                                                        \


#endif      // __TRACE_H__