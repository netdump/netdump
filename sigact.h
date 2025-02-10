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

#ifndef __SIGACT_H__
#define __SIGACT_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "common.h"

/**
 * @brief 
 * 	Define signals and related signal processing functions and properties
 * @memberof 
 * 	sig The integer value of the signal
 * @memberof 
 * 	sa Variables of type struct sigaction
 */
typedef struct {

	int sig;
	struct sigaction sa;

} sigact_t;


#define SIGACT_STACK_INFO		"stackinfo"


/**
 * @brief 
 * 	The processing process receives the child process exit signal
 * @param signum 
 * 	Signal number
 */
void sigact_handle_child_quit (int signum);


/**
 * @brief 
 * 	The process received an exit signal
 * @param signum 
 * 	Signal number
 */
void sigact_handle_quit (int signum);


/**
 * @brief 
 * 	Handling signals that cause program crashes
 * @param signum 
 * 	Signal number
 */
void sigact_handle_crash (int signum);


/**
 * @brief 
 * 	Register signal processing
 */
int sigact_register_signal_handle (void);

/**
 * @brief
 * 	When the parent process exits,
 * 	the child process can also receive the signal that the parent process exits
 */
void sigact_called_prctl_set_value(void);

#endif  // __SIGACT_H__
