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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/version.h>
#include "trace.h"
#include "common.h"


/**
 * @brief Global process number
 */
uint32_t GCOREID = 0;


/**
 * @brief Check if the kernel version is greater than 2.6.6 
 * @note
 *  If the kernel version is less than 2.6.6, 
 *  the program will exit because the program uses mq_open and other related APIs.
 */
void nd_check_kernel_version(void) {

    if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 6)) 
        fprintf(stderr, "Kernel version is less than 2.6.6\n");

    return ;
}
