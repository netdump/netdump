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

#ifndef __COMMON_H__
#define __COMMON_H__


/**
 * @brief Major version number
 */
#define NETDUMP_MAJOR_VERSION           0x0001U
#define MAJOR_V                         NETDUMP_MAJOR_VERSION
/**
 * @brief Subversion number
 */
#define NETDUMP_SUB_VERSION             0x0001U
#define SUB_V                           NETDUMP_SUB_VERSION


/** C99：编译时使用 -std=c99，编译器会定义 __STDC_VERSION__ 宏为 199901L */
/** C89：编译时使用 -std=c89，编译器会定义 __STDC_VERSION__ 宏为 199409L */
/** C99 */
#if __STDC_VERSION__ >= 199901L

#include <stdint.h>
#include <stdbool.h>

#else 

#define true                1
#define false               0

typedef char                int8_t;
typedef unsigned char       uint8_t;
typedef unsigned char       bool;

typedef char *              int8_t *;

typedef short               int16_t;
typedef unsigned short      uint16_t;

typedef int                 int32_t;
typedef unsigned int        uint32_t;

typedef long long           int64_t;
typedef unsigned long long  uint64_t;

#endif



/**
 * @brief Error Code
 */
enum {
    ND_OK,
    ND_ERR,
};


/** DISPLAY PROCESS ID */
#define GCOREID_DP      0U
/** CAPTURE PROCESS ID */
#define GCOREID_CP      1U
/** ANALYSIS PROCESS ID */
#define GCOREID_AA      2U


/**
 * @brief Global process number
 */
extern uint32_t GCOREID;

/**
 * @brief Get the GCOREID of the current process
 */
__extern_always_inline uint32_t lcore_id(void) {

    return GCOREID;
}


/**
 * @brief Check if the kernel version is greater than 2.6.6 
 * @note
 *  If the kernel version is less than 2.6.6, 
 *  the program will exit because the program uses mq_open and other related APIs.
 */
void nd_check_kernel_version(void);


/**
 * @brief Check if the kernel version is greater than 2.6.6 
 */
#define ND_CHECK_KERNEL_VERSION()   do{nd_check_kernel_version();} while(0);


/**
 * Check if a branch is likely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * likely to be taken. Example:
 *
 *   if (likely(x > 1))
 *      do_stuff();
 *
 */
#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif /* likely */

/**
 * Check if a branch is unlikely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * unlikely to be taken. Example:
 *
 *   if (unlikely(x < 1))
 *      do_stuff();
 *
 */
#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif /* unlikely */



#endif 