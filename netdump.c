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
#include "display.h"
#include "sigact.h"
#include "common.h"
#include "trace.h"
#include "msgcomm.h"


int main(int argc, char ** argv) {

    ND_CHECK_KERNEL_VERSION();

    TRACE_STARTUP();

    TC("Called { %s (%d, %p)", __func__, argc, argv);

    if(unlikely((msgcomm_startup()) == ND_ERR)) {
        T("Msgcomm startup failed");
        goto label1;
    }

    msgcomm_infodump();

    if (unlikely(((sigact_register_signal_handle()) == ND_ERR))) {
        T("Register signal handle failed");
        goto label2;
    }

    display_startup_TUI_showcase();

label2:

    msgcomm_ending();
    
label1:

    TRACE_DESTRUCTION();

    return 0;;
}