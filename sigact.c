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
#include <sys/wait.h>
#include <sys/stat.h>
#include "sigact.h"
#include "common.h"
#include "trace.h"
#include "msgcomm.h"
#include "capture.h"

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
 * 12. SIGHUP - 默认情况下，SIGHUP 信号会导致进程终止（退出）
 * 	默认情况下，SIGHUP 信号会导致进程终止（退出）
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
 * 13. SIGPIPE - 是一个信号，默认行为是终止进程。
 * 	它的主要作用是提醒进程：写入操作的目标已经不可用，通常是管道、套接字或 FIFO 的读取端已经关闭。
 *
 */

static sigact_t sigact[] = {

	{.sig = SIGSEGV, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGFPE, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGILL, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGBUS, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGABRT, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},
	{.sig = SIGHUP, .sa.sa_handler = sigact_handle_crash, .sa.sa_flags = SA_RESTART},

	{.sig = SIGQUIT, .sa.sa_handler = sigact_handle_quit, .sa.sa_flags = SA_RESTART},
	{.sig = SIGINT, .sa.sa_handler = sigact_handle_quit, .sa.sa_flags = SA_RESTART},
	{.sig = SIGTERM, .sa.sa_handler = sigact_handle_quit, .sa.sa_flags = SA_RESTART},
	{.sig = SIGPIPE, .sa.sa_handler = sigact_handle_quit, .sa.sa_flags = SA_RESTART},

	{.sig = SIGCHLD, .sa.sa_handler = sigact_handle_child_quit, .sa.sa_flags = SA_RESTART},

	{.sig = -1, .sa.sa_handler = NULL, .sa.sa_flags = SA_RESTART}

};

/**
 * @brief 
 * 	TUI shows process exit resource destruction
 */
extern void display_exit_resource_destruction();


/**
 * @brief 
 * 	addr2line useage
 * 	addr2line -e <可执行文件> <内存地址>
 * 	-e <可执行文件>：指定要进行符号解析的可执行文件（即包含调试符号的文件）
 * 	<内存地址>：给定的内存地址，它通常是堆栈跟踪（stack trace）输出中的地址
 * 	-f：在输出中包含函数名称。没有 -f 时，addr2line 只返回源文件的行号
 * 	
 * @example
 * 	addr2line -e ./program -f 0x00400667
 * 	addr2line -e ./program -f 0x00400667 0x00400512 0x0040043a
 */


/**
 * @brief 
 * 	Generate stack trace to file
 * @param signum
 * 	signal numbers
 */
static void sigact_Generate_stack_trace (int signum) {

	TC("Called { %s ()", __func__);

	void *array[10];
    size_t size;

	if ((access(SIGACT_STACK_INFO, F_OK) == 0)) {
		unlink(SIGACT_STACK_INFO);
	}

    size = backtrace(array, 16);

	int fd = open(SIGACT_STACK_INFO, O_RDWR |O_CREAT, 0666);

	char space[64] = {0};
	snprintf(space, 64, "lCOREID: %d; PID: %d; SIGNUM: %d\n", lcore_id(), getpid(), signum);
	write(fd, space, strlen(space));

	backtrace_symbols_fd(array, size, fd);

	close(fd);

	RVoid();
}


/**
 * @brief 
 * 	Handling signals that cause program crashes
 * @param signum 
 * 	Signal number
 */
void sigact_handle_crash (int signum) {

	TC("Called { %s(%d)", __func__, signum);

	sigact_Generate_stack_trace(signum);

	unsigned int lCOREID = lcore_id();

	TI("lCOREID: %u", lCOREID);

	if (GCOREID_DP == lCOREID) {
		display_exit_resource_destruction();
		msgcomm_ending();
	}
	else if (GCOREID_CP == lCOREID)
	{
		capture_sig_handle();
	}

	TRACE_DESTRUCTION();

	exit(signum);

	RVoid();
}


/**
 * @brief 
 * 	The process received an exit signal
 * @param signum 
 * 	Signal number
 */
void sigact_handle_quit (int signum) {

	TC("Called { %s(%d)", __func__, signum);

	unsigned int lCOREID = lcore_id();

	TI("lCOREID: %u", lCOREID);

	if (GCOREID_DP == lCOREID) {
		display_exit_resource_destruction();
		msgcomm_ending();
	}
	else if (GCOREID_CP == lCOREID)
	{
		capture_sig_handle();
	}

	TRACE_DESTRUCTION();

	exit(signum);

	RVoid();
}


/**
 * @brief 
 * 	Generic processing code for child process exit signal
 * @param pid
 * 	Child process pid
 */
static void sigact_general_code (pid_t pid) {

	TC("Called { %s(%d)", __func__, pid);

	if (pid == childpid[GCOREID_CP]) {
		childpid[GCOREID_CP] = 0;
		if (childpid[GCOREID_AA]) {
			kill(childpid[GCOREID_AA], SIGTERM);
		}
	}
	if (pid == childpid[GCOREID_AA]) {
		childpid[GCOREID_AA] = 0;
		if (childpid[GCOREID_CP]) {
			kill(childpid[GCOREID_CP], SIGTERM);
		}
	}

	RVoid();
}


/**
 * @brief 
 * 	The processing process receives the child process exit signal
 * @param signum 
 * 	Signal number
 */
void sigact_handle_child_quit (int signum) {

	TC("Called { %s(%d)", __func__, signum);

	int status;
	pid_t pid = wait(&status);
	if (pid > 0) {
		if (WIFEXITED(status)) {

			TI("Child process %d exited with status %d", pid, WEXITSTATUS(status));
			sigact_general_code (pid);

		} else if (WIFSIGNALED(status)) {

			TI("Child process %d exited due to signal %d", pid, WTERMSIG(status));
			sigact_general_code (pid);

		} else {

			TI("Child process %d exited abnormally", pid);
			sigact_general_code (pid);
			
		}
	}

	if ((childpid[GCOREID_CP] == 0) && (childpid[GCOREID_AA] == 0)) {
        kill(getpid(), SIGTERM);
    }

	RVoid();
}


/**
 * @brief 
 * 	Register signal processing
 */
int sigact_register_signal_handle (void) {

	TC("Called { %s(void)", __func__);

	int i = 0, num = (sizeof(sigact) / sizeof(sigact_t));

	for (i = 0; i < num; i++) {
		if (((sigact[i].sig) != -1)) {
			if (sigaction(sigact[i].sig, &(sigact[i].sa), NULL) < 0) {
				return ND_ERR;
			}
		}
	}

	RInt(ND_OK);
}

