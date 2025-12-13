
#include "d2c_comm.h"

netdump_shared_t d2c_comm_t d2c_comm;

netdump_shared_t d2c_flag_statistical_t d2c_flag_statistical;

/**
 * @brief
 *  Inter-process communication resource initialization operation
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int d2c_comm_startup(void)
{
    TC("Called { %s(void)", __func__);

    memset(&d2c_comm, 0, sizeof(d2c_comm_t));
    memset(&d2c_flag_statistical, 0, sizeof(d2c_flag_statistical));

    size_t pagesz = sysconf(_SC_PAGESIZE);
    mlock(&d2c_flag_statistical, pagesz);

    RInt(ND_OK);
}

/**
 * @brief
 *  display send message to capture
 * @memberof msg
 *  pointer to the message to be sent
 */
int d2c_comm_send_msg_2_capture (char * msg){

    TC("Called { %s(%s)", __func__, msg);

    memset((char *)&(d2c_comm.d2c_msg), 0, sizeof(desc_comm_msg_t));

    d2c_comm.d2c_msg.direction = D2C_COMM_DIR_0TO1;
    d2c_comm.d2c_msg.msgtype = D2C_COMM_CMD;
    d2c_comm.d2c_msg.length = strlen(msg);
    d2c_comm.d2c_msg.content = msg;

    __atomic_store_n(&(d2c_comm.d2c_msg_complate_flag), 0x01, __ATOMIC_SEQ_CST);

    RInt(ND_OK);
}

/**
 * @brief
 *  capture send message to display
 * @memberof msgtype
 * @memberof msg
 *  pointer to the message to be sent
 */
int d2c_comm_send_msg_2_display(unsigned int msgtype, char *msg) {

    TC("Called { %s(%s)", __func__, msg);

    memset((char *)&(d2c_comm.c2d_msg), 0, sizeof(desc_comm_msg_t));

    d2c_comm.c2d_msg.direction = D2C_COMM_DIR_1TO0;
    d2c_comm.c2d_msg.msgtype = msgtype;
    d2c_comm.c2d_msg.length = strlen(msg);
    d2c_comm.c2d_msg.content = msg;

    __atomic_store_n(&(d2c_comm.c2d_msg_complate_flag), 0x01, __ATOMIC_SEQ_CST);

    RInt(ND_OK);
}

/**
 * @brief
 *  recv msg from capture
 * @memberof msg
 *  Store the received content
 */
int d2c_comm_recv_msg_from_capture(desc_comm_msg_t * msg) {

    TC("Called { %s(%p)", __func__, msg);

    for (;;) {
        int val = __atomic_load_n(&(d2c_comm.c2d_msg_complate_flag), __ATOMIC_SEQ_CST);
        if (!val) {
            nd_delay_microsecond(0, 10000000);
            continue;
        }
        break;
    }

    *msg = d2c_comm.c2d_msg;

    __atomic_store_n(&(d2c_comm.c2d_msg_complate_flag), 0x0, __ATOMIC_SEQ_CST);

    RInt(ND_OK);
}

/**
 * @brief
 *  recv msg from display
 * @memberof msg
 *  Store the received content
 */
int d2c_comm_recv_msg_from_display(desc_comm_msg_t *msg) {

    TC("Called { %s(%p)", __func__, msg);

    for (;;) {
        int val = __atomic_load_n(&(d2c_comm.d2c_msg_complate_flag), __ATOMIC_SEQ_CST);
        if (!val)
        {
            nd_delay_microsecond(0, 10000000);
            continue;
        }
        break;
    }

    *msg = d2c_comm.d2c_msg;

    __atomic_store_n(&(d2c_comm.d2c_msg_complate_flag), 0x0, __ATOMIC_SEQ_CST);

    RInt(ND_OK);
}