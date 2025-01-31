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

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "common.h"
#include "trace.h"
#include "sigact.h"


/**
 * @brief 
 *  The main function of the packet capture function
 * @param COREID
 *  COREID corresponding to the packet capture process
 * @param pname
 *  The name of the packet capture process
 * @param param
 *  Retain Parameters
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_main (unsigned int COREID, const char * pname, void * param);

#endif  // __CAPTURE_H__