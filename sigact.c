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
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sigact.h"
#include "common.h"
#include "trace.h"

/**
 * Common signals that cause process crashes
 * 
 * 1. SIGSEGV - Segmentation Fault (段错误)
 * 	当进程访问无效内存（例如访问空指针、越界访问数组等）时，会收到这个信号
 * 
 * 2. SIGFPE - Floating Point Exception (浮点异常)
 * 	通常在进行非法浮点操作时（例如除以零、溢出等）会收到该信号
 * 
 * 3. SIGILL - Illegal Instruction (非法指令)
 * 	当进程尝试执行无效指令时，会收到此信号
 * 
 * 4. SIGBUS - Bus Error (总线错误)
 * 	当进程访问一个无法映射到物理内存的地址时（例如对未对齐的内存访问），会收到此信号
 * 
 * 5. SIGABRT - Abort (进程中止)
 * 	通常通过 abort() 函数主动触发该信号。该信号也会在程序崩溃时触发（例如由标准库函数内部的错误引发）
 * 
 * 6. SIGQUIT - Quit (退出)
 * 	用户发送 Ctrl+\ 时会触发该信号，通常会产生 core dump
 * 
 * 7. SIGTRAP - Trace Trap (跟踪陷阱)
 * 	当程序遇到调试器设置的断点或者调试陷阱时，触发此信号
 * 
 * 8. SIGKILL - Kill (强制终止) [不可捕获]
 * 	这是一个不能被捕获、阻塞或忽略的信号。它会立即终止进程，通常由管理员或操作系统发送
 * 
 * 9. SIGSTOP - Stop (停止进程) [不可捕获]
 * 	与 SIGKILL 类似，SIGSTOP 也是不能被捕获、阻塞或忽略的信号。它会使进程停止运行
 * 
 * 10. SIGINT - Interrupt Signal (中断信号)
 * 	SIGINT 信号通常通过用户按下 Ctrl+C 触发, 它是用来中断正在运行的进程的
 * 
 * 11. SIGTERM - 终止信号
 * 	通常用于请求程序终止，它不会导致进程崩溃，可以捕获并处理来执行清理操作
 * 
 * 12. SIGCHLD - 当子进程终止或停止时，父进程会收到一个 SIGCHLD 信号
 * 	
 */


static sigact_t sigact[] = {

	{.sig = SIGSEGV, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGFPE, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGILL, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGBUS, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGABRT, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},

	{.sig = SIGQUIT, .sa.sa_handler = sigact_handle_quit, .sa.sa_flags = SA_RESTART},
	{.sig = SIGINT, .sa.sa_handler = sigact_handle_quit, .sa.sa_flags = SA_RESTART},
	{.sig = SIGTERM, .sa.sa_handler = sigact_handle_quit, .sa.sa_flags = SA_RESTART},
	
	{.sig = SIGCHLD, .sa.sa_handler = sigact_handle_child_quit, .sa.sa_flags = SA_RESTART},

	{.sig = -1, .sa.sa_handler = NULL, .sa.sa_flags = SA_RESTART}	

};


/**
 * @brief Generate stack trace to file
 */
static void sigact_Generate_stack_trace (void) {

	void *array[10];
    size_t size;

	if ((access(SIGACT_STACK_INFO, F_OK) == 0)) {
		unlink(SIGACT_STACK_INFO);
	}

    size = backtrace(array, 10);

	int fd = open(SIGACT_STACK_INFO, O_RDWR |O_CREAT, 0666);

    backtrace_symbols_fd(array, size, fd);

	close(fd);

	return ;
}


/**
 * @brief Handling signals that cause program crashes
 * @param signum Signal number
 */
void sigact_handle_crash (int signum) {

	sigact_Generate_stack_trace();

	exit(1);

	return ;
}


/**
 * @brief The process received an exit signal
 * @param signum Signal number
 */
void sigact_handle_quit (int signum) {

	exit(1);

	return ;
}


/**
 * @brief The processing process receives the child process exit signal
 * @param signum Signal number
 */
void sigact_handle_child_quit (int signum) {

	exit(1);

	return ;
}


/**
 * @brief Register signal processing
 */
int sigact_register_signal_handle (void) {

	int i = 0, num = (sizeof(sigact) / sizeof(sigact_t));

	for (i = 0; i < num; i++) {
		if (((sigact[i].sig) != -1)) {
			if (sigaction(sigact[i].sig, &(sigact[i].sa), NULL) < 0) {
				return ND_ERR;
			}
		}
	}

	return ND_OK;
}

