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
#include <locale.h>
#include "netdump.h"


int main(int argc, char ** argv) {

    setlocale(LC_ALL, "");

    if (geteuid() != 0)
    {
        fprintf(stderr, "\n\tOperation not permitted!\n\n\tNeed root privileges to use!\n\n");
        return 1;
    }

    ND_CHECK_KERNEL_VERSION();

    TRACE_STARTUP();

    TC("Called { %s (%d, %p)", __func__, argc, argv);

    sigact_called_prctl_set_value();

    if (unlikely(comm_zone_startup()) == ND_ERR)
    {
        TE("comm zone startup failed");
        goto label1;
    }

    if (unlikely((c2a_comm_startup()) == ND_ERR))
    {
        TE("ctoacomm startup failed");
        goto label2;
    }

    a2d_comm_startup();
    d2c_comm_startup();

    fflush(trace_G_log);

    if (unlikely((netdump_fork(GCOREID_CP, "capture", capture_main)) == ND_ERR)) {
        TE("Fork Capture failed");
        goto label3;
    }

    if (unlikely((netdump_fork(GCOREID_AA, "analysis", analysis_main)) == ND_ERR)) {
        TE("Fork Analysis failed");
        kill(childpid[GCOREID_CP], SIGTERM);
        goto label4;
    }

    if (unlikely(((sigact_register_signal_handle()) == ND_ERR))) {
        TE("Register signal handle failed");
        goto label4;
    }

    display_startup_TUI_showcase();

label4:

    netdump_kill();

label3:

    c2a_comm_ending();

label2:

    comm_zone_ending();

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


/**
 * @brief
 *  Killing a child process
 */
void netdump_kill(void) {

    TC("Called { %s(void)", __func__);

    if (childpid[GCOREID_CP]) {
        kill(childpid[GCOREID_CP], SIGTERM);
        nd_delay_microsecond(0, 10000000);
    }

    if (childpid[GCOREID_AA]) {
        kill(childpid[GCOREID_AA], SIGTERM);
        nd_delay_microsecond(0, 10000000);
    }

    if ((childpid[GCOREID_CP] == 0) && (childpid[GCOREID_AA] == 0)) {
        kill(getpid(), SIGTERM);
        nd_delay_microsecond(0, 10000000);
    }

    RVoid();
}