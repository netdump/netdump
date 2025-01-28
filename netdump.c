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


int main(int argc, char ** argv) {

    sigact_register_signal_handle();

    display_startup_TUI_showcase();
    display_exit_TUI_showcase();

    return 0;
}