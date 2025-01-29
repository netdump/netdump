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

    TC("Called { %s (%d, %p)", __func__, argc, argv);

    TRACE_STARTUP();

    sigact_register_signal_handle();

    display_startup_TUI_showcase();
    display_exit_TUI_showcase();

    RInt(0);
}