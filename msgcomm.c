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


#include "msgcomm.h"
#include "common.h"
#include "trace.h"


/**
 * @brief 
 *  Global variables for message communication, 
 *  used for initialization and release
 * @memberof [0]    0TO1
 * @memberof [1]    1TO0
 */
static msgcomm_t msgcomm[] = {
    {
        .comm.ring = NULL,
        .comm._ring = NULL,
        .comm.baseaddr = MSGCOMM_BASE_ADDR_RING0TO1,
        .comm._baseaddr = MSGCOMM_BASE_ADDR__RING0TO1,
        .comm.count = MSGCOMM_BLOCK_NUMBERS,
        .comm.name = MSGCOMM_RING_FNAME_0TO1,
        .comm._name = MSGCOMM__RING_FNAME_0TO1,

        .msg.memory = NULL,
        .msg.baseaddr = MSGCOMM_BASE_ADDR_MEM0TO1,
        .msg.dir = MSGCOMM_DIR_0TO1,
        .msg.memspace = MSGCOMM_MEMORY_SPACE,
        .msg.name = MSGCOMM_MEM_FNAME_0TO1
    }, 
    {
        .comm.ring = NULL,
        .comm._ring = NULL,
        .comm.baseaddr = MSGCOMM_BASE_ADDR_RING1TO0,
        .comm._baseaddr = MSGCOMM_BASE_ADDR__RING1TO0,
        .comm.count = MSGCOMM_BLOCK_NUMBERS,
        .comm.name = MSGCOMM_RING_FNAME_1TO0,
        .comm._name = MSGCOMM__RING_FNAME_1TO0,

        .msg.memory = NULL,
        .msg.baseaddr = MSGCOMM_BASE_ADDR_MEM1TO0,
        .msg.dir = MSGCOMM_DIR_1TO0,
        .msg.memspace = MSGCOMM_MEMORY_SPACE,
        .msg.name = MSGCOMM_MEM_FNAME_1TO0
    }

};


/**
 * @brief 
 *  Initialize the msgcomm_t structure
 * @param vmsgcomm
 *  msgcomm_t structure pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int msgcomm_init_msgcomm(msgcomm_t * vmsgcomm) {

    TC("Called { %s(%p)", __func__, vmsgcomm);

    if (unlikely((nd_check_fpath(vmsgcomm->comm.name)) == ND_ERR))
        RInt(ND_ERR);

    if (unlikely((nd_check_fpath(vmsgcomm->comm._name)) == ND_ERR))
        RInt(ND_ERR);
    
    if (unlikely((nd_check_fpath(vmsgcomm->msg.name)) == ND_ERR))
        RInt(ND_ERR);
    
    vmsgcomm->comm.ring = ring_create (
        vmsgcomm->comm.name, 
        (uintptr_t)(vmsgcomm->comm.baseaddr), 
        vmsgcomm->comm.count, 0
    );

    if (unlikely((!(vmsgcomm->comm.ring)))) {
        T("errmsg: vmsgcomm->comm.ring: %p", vmsgcomm->comm.ring);
        RInt(ND_ERR);
    }

    vmsgcomm->comm._ring = ring_create (
        vmsgcomm->comm._name, 
        (uintptr_t)(vmsgcomm->comm._baseaddr), 
        vmsgcomm->comm.count, 0
    );

    if (unlikely((!(vmsgcomm->comm._ring)))) {
        T("errmsg: vmsgcomm->comm.ring: %p", vmsgcomm->comm.ring);
        RInt(ND_ERR);
    }
    
    vmsgcomm->msg.memory = nd_called_open_mmap_openup_memory (
        vmsgcomm->msg.name,
        vmsgcomm->msg.baseaddr,
        vmsgcomm->msg.memspace,
        vmsgcomm->comm.count
    );

    if (unlikely((!(vmsgcomm->msg.memory)))) {
        T("errmsg: vmsgcomm->comm.ring: %p", vmsgcomm->comm.ring);
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Destroy msgcomm_t structure members
 * @param vmsgcomm
 *  msgcomm_t structure pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int msgcomm_ending_msgcomm(msgcomm_t * vmsgcomm) {

    TC("Called { %s(%p)", __func__, vmsgcomm);

    if (unlikely((!(vmsgcomm->comm.ring)))) {
        T("errmsg: vmsgcomm->comm.ring is null");
    }
    else {
        ring_free(vmsgcomm->comm.ring);
    }
    unlink(vmsgcomm->comm.name);

    if (unlikely((!(vmsgcomm->comm._ring)))) {
        T("errmsg: vmsgcomm->comm._ring is null");
    }
    else {
        ring_free(vmsgcomm->comm._ring);
    }
    unlink(vmsgcomm->comm._name);

    if (unlikely((!(vmsgcomm->msg.memory)))) {
        T("errmsg: vmsgcomm->msg.memory is null");
    }
    else {
        munmap(vmsgcomm->msg.memory, (vmsgcomm->msg.memspace * vmsgcomm->comm.count));
    }
    unlink(vmsgcomm->msg.name);

    RInt(ND_OK);
}


/**
 * @brief 
 *  Enqueue the message memory space into the message communication queue
 * @param vmsgcomm
 *  msgcomm_t structure pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int msgcomm_enq_ring(msgcomm_t * vmsgcomm) {

    TC("Called { %s(%p)", __func__, vmsgcomm);

    ring_t * ring = (ring_t *)(vmsgcomm->comm._ring);

    int i = 0;
    for (i = 0; i < (vmsgcomm->comm.count - 1); i++) {
        if (unlikely((ring_enqueue(ring, (void *)(vmsgcomm->msg.memory + (i * vmsgcomm->msg.memspace))) != 0))) {
            T("errmsg: called ring_enqueue failed;[i: %d]", i);
            RInt(ND_ERR);
        }
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  Filling Address
 * @param dir
 *  Message direction
 * @param ring
 *  The secondary pointer that needs to be filled
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int msgcomm_filladdr(unsigned int dir, ring_t **ring) {

    TC("Called { %s(%u, %p)", __func__, dir, ring);

    if (unlikely(!ring)) {
        T("errmsg: ring is null");
        RInt(ND_ERR);
    }

    switch (dir) {
        case MSGCOMM_DIR_0TO1:
            *ring = msgcomm[0].comm.ring;
            break;
        case MSGCOMM_DIR_1TO0:
            *ring = msgcomm[1].comm.ring;
            break;
        default:
            T("errmsg: msg dir error; dir: %u", dir);
            RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Message communication resource initialization and startup
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_startup(void) {

    TC("Called { %s()", __func__);

    int i = 0;
    for (i = 0; i < (sizeof(msgcomm) / sizeof(msgcomm_t)); i++) {

        if (unlikely(((msgcomm_init_msgcomm(&(msgcomm[i]))) == ND_ERR)))
            RInt(ND_ERR);

        if (unlikely(((msgcomm_enq_ring(&(msgcomm[i]))) == ND_ERR)))
            RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Message communication resource destruction and exit
 */
void msgcomm_ending(void) {

    TC("Called { %s()", __func__);

    int i = 0;
    for (i = 0; i < (sizeof(msgcomm) / sizeof(msgcomm_t)); i++) {
        msgcomm_ending_msgcomm(&(msgcomm[i]));
    }

    RVoid();
}


/**
 * @brief 
 *  Message communication module sends messages
 * @param dir
 *  Message direction
 * @param msgtype
 *  Message Type
 * @param msg
 *  Message content
 * @param length
 *  Message length
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_sendmsg(unsigned int dir, unsigned int msgtype, const char * msg, int length) {

    TC("Called { %s(%u, %u, %s, %d)", __func__, dir, msgtype, msg, length);

    if (unlikely((!msg))) {
        T("errmsg: msg is null");
    }

    ring_t * _ring = NULL, * ring = NULL;

    if (unlikely(msgcomm_filladdr(dir, &ring) == ND_ERR)) {
        T("errmsg: called msgcomm_filladdr failed");
        RInt(ND_ERR);
    }

    if (unlikely(msgcomm_filladdr(dir, &_ring) == ND_ERR)) {
        T("errmsg: called msgcomm_filladdr failed");
        RInt(ND_ERR);
    }

    if (unlikely((!ring) || (!_ring))) {
        T("errmsg: ring: %p; _ring: %p", ring, _ring);
        RInt(ND_ERR);
    }

    void * obj = NULL;
    if (unlikely(ring_dequeue(_ring, &obj) != 0)) {
        T("errmsg: called ring_dequeue failed");
        RInt(ND_ERR);
    }

    if (unlikely(!obj)) {
        T("errmsg: obj is null");
        RInt(ND_ERR);
    }

    message_t * message = (message_t *)(obj);
    message->dir = dir;
    message->msgtype = msgtype;
    message->length = length;
    memcpy(message->msg, msg, length);
    
    if (unlikely((ring_enqueue(ring, obj) != 0))) {
        T("errmsg: called ring_enqueue failed");
        memset(obj, 0, MSGCOMM_MEMORY_SPACE);
        ring_enqueue(_ring, obj);
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Message communication module receives messages
 * @param 
 *  Message direction
 * @param message
 *  The message to be sent
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_recvmsg(unsigned int dir, message_t * message) {

    TC("Called { %s(%u, %p)", __func__, dir, message);

    if (unlikely((!message))) {
        T("errmsg: message is null");
        RInt(ND_ERR);
    }

    ring_t * _ring = NULL, * ring = NULL;

    if (unlikely(msgcomm_filladdr(dir, &ring) == ND_ERR)) {
        T("errmsg: called msgcomm_filladdr failed");
        RInt(ND_ERR);
    }

    if (unlikely(msgcomm_filladdr(dir, &_ring) == ND_ERR)) {
        T("errmsg: called msgcomm_filladdr failed");
        RInt(ND_ERR);
    }

    if (unlikely((!ring) || (!_ring))) {
        T("errmsg: ring: %p; _ring: %p", ring, _ring);
        RInt(ND_ERR);
    }

    unsigned int nums = ring_count(ring);
    if (nums <= 0 || nums > MSGCOMM_BLOCK_NUMBERS) {
        T("errmsg: the number of elements in the queue: %u", nums);
        RInt(ND_ERR);
    }

    void * obj = NULL;
    if (unlikely((ring_dequeue(ring, &obj) != 0))) {
        T("errmsg: called ring_dequeue failed");
        RInt(ND_ERR);
    }

    message_t * tmp = (message_t *)(obj);

    message->dir = tmp->dir;
    message->msgtype = tmp->msgtype;
    message->length = tmp->length;
    if (tmp->length) 
        memcpy(message->msg, tmp->msg, tmp->length);

    if (unlikely((ring_enqueue(_ring, obj) != 0))) {
        T("errmsg: called ring_enqueue failed");
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  Check whether there is a message in the specified direction
 * @param dir
 *  Message direction
 * @return
 *  If it exists, it returns the number of messages.
 */
unsigned int msgcomm_detection(unsigned int dir) {

    TC("Called { %s(%u)", __func__, dir);

    ring_t * ring = NULL;

    if (unlikely(msgcomm_filladdr(dir, &ring) == ND_ERR)) {
        T("errmsg: called msgcomm_filladdr failed");
        RInt(0);
    }

    if (unlikely((!ring))) {
        T("errmsg: ring: %p; _ring: %p", ring);
        RInt(0);
    }

    unsigned int nums = ring_count(ring);

    RInt(nums);
}


/**
 * @brief
 *  Global variable msgcomm member information output
 */
void msgcomm_infodump(void) {

    TC("Called { %s()", __func__);

    int i = 0;
    for (i = 0; i < (sizeof(msgcomm) / sizeof(msgcomm_t)); i++) {
        T("infomsg: msgcomm[%d]", i);
        T("msgcomm[%d].comm.name: %s", i, msgcomm[i].comm.name);
        T("msgcomm[%d].comm.baseaddr: %p", i, msgcomm[i].comm.baseaddr);
        T("msgcomm[%d].comm.ring: %p", i, msgcomm[i].comm.ring);
        
        T("msgcomm[%d].comm._name: %s", i, msgcomm[i].comm._name);
        T("msgcomm[%d].comm._baseaddr: %p", i, msgcomm[i].comm._baseaddr);
        T("msgcomm[%d].comm._ring: %p", i, msgcomm[i].comm._ring);
        
        T("msgcomm[%d].comm.count: %u", i, msgcomm[i].comm.count);

        T("msgcomm[%d].msg.name: %s", i, msgcomm[i].msg.name);
        T("msgcomm[%d].msg.baseaddr: %p", i, msgcomm[i].msg.baseaddr);
        T("msgcomm[%d].msg.memory: %p", i, msgcomm[i].msg.memory);
        T("msgcomm[%d].msg.memspace: %u", i, msgcomm[i].msg.memspace);
        T("msgcomm[%d].msg.dir: %u", i, msgcomm[i].msg.dir);
    }

    RVoid();
}


/**
 * @brief 
 *  Calling this interface can complete a message sending
 * @param dir
 *  Message direction
 * @param msgtype
 *  Message Type
 * @param msg
 *  Message content
 * @param length
 *  Message length
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_message_send(unsigned int dir, unsigned int msgtype, const char * msg, int length) {

    TC("Called { %s(%u, %u, %s, %d)", __func__, dir, msgtype, msg, length);

    if (unlikely(( 
        ((dir != MSGCOMM_DIR_0TO1) && (dir != MSGCOMM_DIR_1TO0)) || 
        (msgtype < 0xF0 || msgtype > 0xF3) || (!msg) || (length < 0)
    ))) {
        T("errmsg: Param is error");
        RInt(ND_ERR);
    }

    if (unlikely((msgcomm_sendmsg(dir, msgtype, msg, length)) == ND_ERR)) {
        T("errmsg: msgcomm_sendmsg error");
        RInt(ND_ERR);
    }

    unsigned int rdir = (dir == MSGCOMM_DIR_0TO1) ? MSGCOMM_DIR_1TO0 : MSGCOMM_DIR_0TO1;

    long timeout = 1;
    int i = 0, count = 1000;
    for (i = 0; i < count; i++) {
        if (msgcomm_detection(rdir)) 
            break;
        nd_delay_microsecond(timeout);
    }

    if (count == 1000) {
        T("errmsg: ACK timeout");
        RInt(ND_ERR);
    }

    message_t message;
    if (unlikely((msgcomm_recvmsg(rdir, &message)) == ND_ERR)) {
        T("errmsg: msgcomm_recvmsg failed");
        RInt(ND_ERR);
    }

    if(unlikely((message.msgtype != 0xF1U))) {
        T("errmsg: message.msgtype is not ack");
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Calling this interface can complete a message reception.
 * @param 
 *  Message direction
 * @param message
 *  The message to be sent
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int msgcomm_message_recv (unsigned int dir, message_t * message) {

    TC("Called { %s(%u, %p)", __func__, dir, message);

    if (unlikely(!message)) {
        T("errmsg: param error");
        RInt(ND_ERR);
    }

    if (!(msgcomm_detection(dir))) {
        T("infomsg: No message can be received");
        RInt(ND_ERR);
    }

    if (unlikely((msgcomm_recvmsg(dir, message)) == ND_ERR)) {
        T("errmsg: msgcomm_recvmsg failed");
        RInt(ND_ERR);
    }

    if (unlikely(
        ((message->dir != MSGCOMM_DIR_0TO1 && message->dir != MSGCOMM_DIR_1TO0) ||
        (message->msgtype > 0xF3u || message->msgtype < 0xF0u)))
    ) {
        T("errmsg: message is error");
        RInt(ND_ERR);
    }

    unsigned int sdir = (dir == MSGCOMM_DIR_0TO1) ? MSGCOMM_DIR_1TO0 : MSGCOMM_DIR_0TO1;

    if (unlikely((msgcomm_sendmsg(sdir, MSGCOMM_ACK, NULL, 0)) == ND_ERR)) {
        T("errmsg: ACK send failed");
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}