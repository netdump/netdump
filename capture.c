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


#include "capture.h"
#include "msgcomm.h"


/**
 * @brief 
 *  The main function of the packet capture function
 * @param COREID
 *  COREID corresponding to the packet capture process
 * @param pname
 *  The name of the packet capture process
 * @param param
 *  Retain Parameters
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_main (unsigned int COREID, const char * pname, void * param) {

    GCOREID = COREID;

    if (trace_G_log) {
        fclose(trace_G_log);
    }

    TRACE_STARTUP();

    TC("Called { %s(%u, %s, %p)", __func__, COREID, pname, param);

    if (unlikely((prctl(PR_SET_NAME, pname, 0, 0, 0)) != 0)) {
        T("errmsg: Prctl set name(%s) failed", pname);
        goto label1;
    }

    if (unlikely(((sigact_register_signal_handle()) == ND_ERR))) {
        T("errmsg: Register signal handle failed");
        goto label1;
    }

    if (unlikely((capture_loop()) == ND_ERR)) {
        T("errmsg: Analysis loop startup failed");
        goto label1;
    }

label1:

    TRACE_DESTRUCTION();

    RInt(ND_OK);
}


/**
 * @brief
 *  The main loop of the packet capture process
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_loop (void) {

    TC("Called { %s(void)", __func__);

    while (1) {

        char space[1024] = {0};
        message_t * message = (message_t *)(space);

        if (unlikely((capture_cmd_from_display (message)) == ND_ERR)) {
            T("errmsg: capture cmd from display failed");
            exit(1);
        }

        T("infomsg:     ");
        T("infomsg: message->dir: %u", message->dir);
        T("infomsg: message->msgtype: %u", message->msgtype);
        T("infomsg: message->length: %u", message->length);
        T("infomsg: message->msg: %s", message->msg);

        if (unlikely(((capture_reply_to_display(MSGCOMM_ERR, "Commad Analysis Failed")) == ND_ERR))) 
        {
            T("errmsg: capture reply to display failed");
            exit(1);
        }

        nd_delay_microsecond(1000);

        getchar();

    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Capture process and display process information exchange
 * @param message
 *  Storing received messages
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_cmd_from_display (message_t * message) {

    TC("Called { %s(%p)", __func__, message);

    if (unlikely((!message))) {
        T("errmsg: param error");
        RInt(ND_ERR);
    }

    if (unlikely((msgcomm_message_recv(MSGCOMM_DIR_0TO1, message)) == ND_ERR)) {
        T("errmsg: msgcomm message recv failed");
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  The capture process responds to the dispaly process
 * @param msgtype
 *  Message Type
 * @param reply
 *  Response message content
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_reply_to_display (unsigned int msgtype, const char * reply) {

    TC("Called { %s(%u, %p)", __func__, msgtype, reply);

    if (unlikely((!reply))) {
		T("errmsg: param error");
		RInt(ND_ERR);
	}

	if ( unlikely(
		((msgcomm_message_send(MSGCOMM_DIR_1TO0, msgtype, reply, strlen(reply))) == ND_ERR)
	))
	{
		T("errmsg: msgcomm message send failed");
		RInt(ND_ERR);
	}

    RInt(ND_OK);
}