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


int main(int argc, char ** argv) {

    ND_CHECK_KERNEL_VERSION();

    TRACE_STARTUP();

    TC("Called { %s (%d, %p)", __func__, argc, argv);

    sigact_register_signal_handle();

    display_startup_TUI_showcase();
    
    TRACE_DESTRUCTION();

    return 0;;
}