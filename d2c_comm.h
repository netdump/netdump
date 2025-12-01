
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

#ifndef __D2C_COMM_H__
#define __D2C_COMM_H__

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdint.h>
#include <stddef.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <setjmp.h>

#include "bpf.h"
#include "pcap/pcap.h"
#include "pcap/dlt.h"

#include "common.h"
#include "trace.h"
#include "ndo.h"

/**
 * @brief
 * 	Passing state values ​​between processes
 * @param address
 * 	The address of the state variable to be passed
 * @param value
 * 	The state value that needs to be passed
 */
#define msgcomm_transfer_status_change(address, value)											\
	do {																						\
		__atomic_store_n((address), value, __ATOMIC_RELEASE);									\
		/*__atomic_thread_fence(__ATOMIC_SEQ_CST);*/											\
	} while (0);


/**
 * @brief
 * 	Passing state values ​​between processes
 * @param address
 * 	The address of the state variable to be passed
 * @param value
 * 	The state value that needs to be passed
 */
#define msgcomm_transfer_status_change_relaxed(address, value)									\
	do {																						\
		__atomic_store_n((address), value, __ATOMIC_RELAXED);									\
		/*__atomic_thread_fence(__ATOMIC_SEQ_CST);*/											\
	} while (0);


/**
 * @brief
 * 	Receive the transmitted status value
 * @param address
 * 	Get the address of the status value
 * @param variable
 * 	Store the obtained status value
 */
#define msgcomm_receive_status_value(address, variable)											\
	do {																						\
		/*__atomic_thread_fence(__ATOMIC_SEQ_CST);*/											\
		variable = __atomic_load_n(address, __ATOMIC_ACQUIRE);									\
	} while (0);


/**
 * @brief
 * 	Receive the transmitted status value
 * @param address
 * 	Get the address of the status value
 * @param variable
 * 	Store the obtained status value
 */
#define msgcomm_receive_status_value_relaxed(address, variable)									\
	do {																						\
		/*__atomic_thread_fence(__ATOMIC_SEQ_CST);*/											\
		variable = __atomic_load_n(address, __ATOMIC_RELAXED);									\
	} while (0);



/**
 * @brief
 * 	Adds a value to the specified variable.
 * @param address
 * 	Specify the address of the data
 * @param value
 *	Accumulated value
 */
#define msgcomm_increase_data_value(address, value)												\
	do {																						\
		__atomic_fetch_add(address, value, __ATOMIC_RELEASE);									\
	} while(0);


/**
 * @brief
 * 	Adds a value to the specified variable.
 * @param address
 * 	Specify the address of the data
 * @param value
 *	Accumulated value
 */
#define msgcomm_increase_data_value_relaxed(address, value)										\
	do {																						\
		__atomic_fetch_add(address, value, __ATOMIC_RELAXED);									\
	} while (0);																	


/**
 * @brief
 * 	Sets the specified variable to zero
 * @param address
 * 	Specify the address of the data
 */
#define msgcomm_zero_variable(address)															\
	do {																						\
		__atomic_store_n(address, 0, __ATOMIC_SEQ_CST);											\
		/*__atomic_thread_fence(__ATOMIC_SEQ_CST);*/											\
	} while(0);

/**
 * @brief Unable to obtain a valid file descriptor
 */
#define C2D_RUN_FLAG_FD_ERR                             (0x01)

/**
 * @brief pcap_breakloop function is called
 */
#define C2D_RUN_FLAG_PCAP_BREAKLOOP_ERR                 (0x02)

/**
 * @brief pcap_dispatch function error
 */
#define C2D_RUN_FLAG_PCAP_DISPATCH_ERR                  (0x04)

/**
 * @brief poll function error
 */
#define C2D_RUN_FLAG_POLL_ERR                           (0x08)

/**
 * @brief Pause Value
 */
#define C2D_RUN_FLAG_PAUSE                              (0x01)

/**
 * @brief Continue Value
 */
#define C2D_RUN_FLAG_CONTINUE                           (0x02)

/**
 * @brief Exit Value
 */
#define C2D_RUN_FLAG_EXIT                               (0x04)

/**
 * @brief Save Value
 */
#define C2D_RUN_FLAG_SAVE                               (0x08)


typedef struct {
    unsigned int d2c_run_flag_val; // _runflag_;
    unsigned int c2d_run_flag_val; // _runflag_c2d;
} d2c_run_flag_t;


typedef struct {
    volatile unsigned long bytes;
    volatile unsigned long packages;
} d2c_statistical_count_t;

extern netdump_shared_t d2c_run_flag_t d2c_run_flag;

extern netdump_shared_t d2c_statistical_count_t d2c_statistical_count;

/**
 * @brief
 *  Communication direction display --> capture 0TO1
 */
#define D2C_COMM_DIR_0TO1   0x01U
/**
 * @brief
 *  Communication direction capture --> display 1TO0
 */
#define D2C_COMM_DIR_1TO0   0x10U

/**
 * @brief
 *  Define the type of communication
 * @memberof D2C_COMM_SUC
 *  Message processed successfully
 * @memberof D2C_COMM_ERR
 *  Message processing error
 * @memberof D2C_COMM_CMD
 *  Command type message
 */
enum
{
    D2C_COMM_SUC = 0xF0U,
    D2C_COMM_ERR = 0XF1U,
    D2C_COMM_CMD = 0xF2U,
    D2C_COMM_FAD = 0xF3U,
    D2C_COMM_HLP = 0xF4U,
    D2C_COMM_DLT = 0xF5U
};

/**
 * @brief
 *  The format used for message communication
 * @memberof dir
 *  direction of message communication
 * @memberof msgtype
 *  types of message communication
 * @memberof content
 *  message content pointer
 */
typedef struct {
    unsigned int direction;
    unsigned int msgtype;
    unsigned int length;
    char * content;
} desc_comm_msg_t;

#define COMM_SHM_ZONE_SIZE          (2048U)

/**
 * @brief define some shared memory used for communication
 */
typedef struct {
    // 存储用户在界面的输入
    char store_user_input[COMM_SHM_ZONE_SIZE]; 
    // 存储在第一个界面显示提示信息的内容
    char store_hint_info[COMM_SHM_ZONE_SIZE]; 
    // 存储 pcap 编译的参数
    char store_compile_argv[COMM_SHM_ZONE_SIZE];
    // 存储 从用户输入转换为 argv 参数
    char store_convert_argv[COMM_SHM_ZONE_SIZE];
    // 存储 第二个界面最底部的 抓包的一些信息
    char store_capture_info[COMM_SHM_ZONE_SIZE];
    // 捕获进程对显示进程的应答
    char store_response_info[COMM_SHM_ZONE_SIZE];

    char d2c_msg_complate_flag;
    char c2d_msg_complate_flag;

    desc_comm_msg_t d2c_msg;
    desc_comm_msg_t c2d_msg;

    ndo_t d2c_ndo;  // ndo

} d2c_comm_t;

extern netdump_shared_t d2c_comm_t d2c_comm;

/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int d2c_comm_startup(void);

/**
 * @brief
 *  display send message to capture
 * @memberof msg
 *  pointer to the message to be sent
 */
int d2c_comm_send_msg_2_capture(char *msg);

/**
 * @brief
 *  capture send message to display
 * @memberof msgtype
 * @memberof msg
 *  pointer to the message to be sent
 */
int d2c_comm_send_msg_2_display(unsigned int msgtype, char *msg);

/**
 * @brief
 *  recv msg from capture
 * @memberof msg
 *  Store the received content
 */
int d2c_comm_recv_msg_from_capture(desc_comm_msg_t *msg);

/**
 * @brief
 *  recv msg from capture
 * @memberof msg
 *  Store the received content
 */
int d2c_comm_recv_msg_from_display(desc_comm_msg_t *msg);

#endif // __D2C_COMM_H_
