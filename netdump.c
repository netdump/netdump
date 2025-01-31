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

#include "netdump.h"


int main(int argc, char ** argv) {

    ND_CHECK_KERNEL_VERSION();

    TRACE_STARTUP();

    TC("Called { %s (%d, %p)", __func__, argc, argv);

    if(unlikely((msgcomm_startup()) == ND_ERR)) {
        T("errmsg: Msgcomm startup failed");
        goto label1;
    }

    msgcomm_infodump();

    if (unlikely((netdump_fork(GCOREID_CP, "capture", capture_main)) == ND_ERR)) {
        T("errmsg: Fork Capture failed");
        goto label2;
    }

    if (unlikely((netdump_fork(GCOREID_AA, "analysis", analysis_main)) == ND_ERR)) {
        T("errmsg: Fork Analysis failed");
        kill(childpid[GCOREID_CP], SIGTERM);
        goto label2;
    }

    if (unlikely(((sigact_register_signal_handle()) == ND_ERR))) {
        T("errmsg: Register signal handle failed");
        goto label2;
    }

    display_startup_TUI_showcase();

label2:

    msgcomm_ending();
    
label1:

    TRACE_DESTRUCTION();

    return 0;;
}


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
int netdump_fork(unsigned int COREID, const char * pname, funcpointer func) {

    TC("Called { %s()", __func__);

    pid_t capture = fork();
    if (0 == capture) {
        func(COREID, pname, NULL);
    }
    else if (unlikely((capture < 0))) {
        RInt(ND_ERR);
    }
    else {
        childpid[COREID] = capture;
    }

    RInt(ND_OK);
}