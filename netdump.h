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

#ifndef __NETDUMP_H__
#define __NETDUMP_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netdump.h"
#include "display.h"
#include "sigact.h"
#include "common.h"
#include "trace.h"
#include "capture.h"
#include "analysis.h"
#include "a2d_comm.h"
#include "d2c_comm.h"


/**
 * @brief 
 *  Create a packet capture subprocess and a packet parsing subprocess
 * @param COREID
 *  COREID corresponding to the child process
 * @param pname
 *  Use this string to modify the name of the process after the process is started
 * @param func
 *  Function executed after the child process is started
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int netdump_fork(unsigned int COREID, const char * pname, funcpointer func);


/**
 * @brief
 *  Killing a child process
 */
void netdump_kill(void);

#endif  // __NETDUMP_H__