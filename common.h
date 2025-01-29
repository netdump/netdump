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


/** DISPLAY PROCESS ID */
#define GCOREID_DP      0
/** CAPTURE PROCESS ID */
#define GCOREID_CP      1
/** ANALYSIS PROCESS ID */
#define GCOREID_AA      2


/**
 * @brief Global process number
 */
unsigned int GCOREID = 0;

/**
 * @brief Get the GCOREID of the current process
 */
__extern_always_inline unsigned int lcore_id(void) {
    
    return GCOREID;
}


#endif 