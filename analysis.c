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


#include "analysis.h"

/**
 * @brief 
 *  The main function of the packet parsing process
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
int analysis_main (unsigned int COREID, const char * pname, void * param) {

    GCOREID = COREID;

    if (trace_G_log) {
        fclose(trace_G_log);
    }

    TRACE_STARTUP();

    TC("Called { %s(%u, %s, %p)", __func__, COREID, pname, param);

    if (unlikely((prctl(PR_SET_NAME, pname, 0, 0, 0)) != 0)) {
        TE ("Prctl set name(%s) failed", pname);
        goto label1;
    }

    if (unlikely(((sigact_register_signal_handle()) == ND_ERR))) {
        TE ("Register signal handle failed");
        goto label1;
    }

    __builtin_prefetch((void *)C2A_COMM_ADDR_ALIGN(c2a_shm_read_addr), 0, 3);

    TC("a2d_info.w3_displayed_max_lines: %d", a2d_info.w3_displayed_max_lines);

    for (;;) 
    {
        if (!a2d_info.w3_displayed_max_lines)
        {
            nd_delay_microsecond(0, 1000000);
            continue;
        }
        break;
    }

    if (unlikely((analysis_loop()) == ND_ERR)) {
        TE ("Analysis loop startup failed");
        goto label1;
    }

label1:

    TRACE_DESTRUCTION();

    RInt(ND_OK);
}

/**
 * @brief
 *  Store captured network frame pointers in order
 */
#define ARRAY_LENGTH        1048576
datastore_t * strore_frame_addr_array[ARRAY_LENGTH] = {NULL};
static unsigned long strore_frame_addr_array_index = 0;


/**
 * @brief 
 *  The main loop of the packet parsing process
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int analysis_loop (void) {

    TC("Called { %s(void)", __func__);

    unsigned int flag = 0;

    for (;;) 
    {
        flag = __atomic_load_n(&(capture_notify_analysis), __ATOMIC_ACQUIRE);
        if (flag)
        {
            if (a2d_info.is_manual_flag)
                analysis_manual_mode();
            else
                analysis_no_manual_mode();
        }
        else 
        {
            if (strore_frame_addr_array_index)
            {
                memset(strore_frame_addr_array, 0, (ARRAY_LENGTH * sizeof(void *)));
                unsigned short tmp_nlines = a2d_info.w3_displayed_max_lines;
                a2d_info.w3_displayed_max_lines = tmp_nlines;
                a2d_comm_startup();
                c2a_shm_read_addr = C2A_COMM_SHM_BASEADDR;
                strore_frame_addr_array_index = 0;
            }
            nd_delay_microsecond(0, 1000000);
        }
    }

    RInt(ND_OK);
}


/**
 * @brief
 *  no manual mode analysis network frame
 */
void analysis_no_manual_mode (void) 
{
    unsigned long tmp = __atomic_load_n(&(d2c_flag_statistical.packages), __ATOMIC_ACQUIRE);

    if (tmp == strore_frame_addr_array_index || tmp == 0 || strore_frame_addr_array_index > tmp)
    {
        if (strore_frame_addr_array_index > tmp)
        {
            memset(strore_frame_addr_array, 0, (ARRAY_LENGTH * sizeof(void *)));
            unsigned short tmp_nlines = a2d_info.w3_displayed_max_lines;
            a2d_info.w3_displayed_max_lines = tmp_nlines;
            a2d_comm_startup();
            c2a_shm_read_addr = C2A_COMM_SHM_BASEADDR;
            strore_frame_addr_array_index = 0;
        }
        else {
            nd_delay_microsecond(0, 1000000);
        }
        return ;
    }

    infonode_t * infonode = analysis_get_infonode();
    if (infonode)
    {
        //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
        analysis_recover_w5node(&(a2d_info.w5_node_idle_list), &(infonode->w5head), &(infonode->w5tail));
        //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
        analysis_recover_l1l2node(
            &(a2d_info.l1l2_node_idle_list), &(infonode->l1l2head), &(infonode->l1l2tail), 
            &(infonode->l1head), &(infonode->l1tail)
        );

        c2a_shm_read_addr = (void *)C2A_COMM_ADDR_ALIGN(c2a_shm_read_addr);

        datastore_t *ds = (datastore_t *)c2a_shm_read_addr;

        strore_frame_addr_array[strore_frame_addr_array_index] = ds;

        infonode->g_store_index = strore_frame_addr_array_index;

        analysis_network_frames((void *)infonode, &(ds->pkthdr), ds->data);

        c2a_shm_read_addr += (sizeof(struct pcap_pkthdr) + ds->pkthdr.len);

        strore_frame_addr_array_index++;

        analysis_putin_infonode(infonode);

        a2d_info.analysis_finished_node_nums++;
    }

    a2d_info.analysis_status_flag = A2D_ANALYSISING;

    if (a2d_info.displayed_status_flag == A2D_DISPLAYED)
        analysis_put_node_into_display_dll();

    a2d_info.analysis_status_flag = A2D_ALALYSISED;

    return ;
}


/**
 * @brief
 *  manul mode analysis network frame
 */
void analysis_manual_mode (void)
{

    int i = 0;
    nd_dll_t * node = NULL;
    infonode_t * infonode = NULL;
    datastore_t *ds = NULL;
    unsigned long index = 0;

    if (a2d_info.w3_displayed_max_lines > a2d_info.w3_displayed_cur_node_nums)
    {
        infonode = container_of(a2d_info.w3_displayed_list_tail, infonode_t, listnode);

        unsigned long tmp = 0;
        msgcomm_receive_status_value(&(d2c_flag_statistical.packages), tmp);
        if (infonode->g_store_index < (tmp - 1))
        {
            infonode = analysis_get_infonode();
            if (infonode)
            {
                //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
                analysis_recover_w5node(&(a2d_info.w5_node_idle_list), &(infonode->w5head), &(infonode->w5tail));
                //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
                analysis_recover_l1l2node(
                    &(a2d_info.l1l2_node_idle_list), &(infonode->l1l2head), &(infonode->l1l2tail),
                    &(infonode->l1head), &(infonode->l1tail)
                );

                c2a_shm_read_addr = (void *)C2A_COMM_ADDR_ALIGN(c2a_shm_read_addr);

                datastore_t *ds = (datastore_t *)c2a_shm_read_addr;

                strore_frame_addr_array[strore_frame_addr_array_index] = ds;

                infonode->g_store_index = strore_frame_addr_array_index;

                analysis_network_frames((void *)infonode, &(ds->pkthdr), ds->data);

                c2a_shm_read_addr += (sizeof(struct pcap_pkthdr) + ds->pkthdr.len);

                strore_frame_addr_array_index++;

                analysis_putin_infonode(infonode);

                a2d_info.analysis_finished_node_nums++;
            }

            a2d_info.analysis_status_flag = A2D_ANALYSISING;

            if (a2d_info.displayed_status_flag == A2D_DISPLAYED)
                analysis_put_node_into_display_dll();

            a2d_info.analysis_status_flag = A2D_ALALYSISED;
        }
    }

    if (a2d_info.analysis_finished_node_nums) {
        for (i = 0; i < a2d_info.analysis_finished_node_nums; i++)
        {
            node = nd_dll_takeout_from_tail(&(a2d_info.analysis_finished_list_head), &(a2d_info.analysis_finished_list_tail));

            infonode = container_of(node, infonode_t, listnode);
            //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
            analysis_recover_w5node(&(a2d_info.w5_node_idle_list), &(infonode->w5head), &(infonode->w5tail));
            //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
            analysis_recover_l1l2node(
                &(a2d_info.l1l2_node_idle_list), &(infonode->l1l2head), &(infonode->l1l2tail),
                &(infonode->l1head), &(infonode->l1tail)
            );

            nd_dll_intsert_into_head_s(&(a2d_info.info_node_idle_list), node);
        }
        a2d_info.analysis_finished_node_nums = 0;
        if (!a2d_info.analysis_finished_list_tail) {
            a2d_info.analysis_finished_list_head = NULL;
        }
    }

    if (a2d_info.is_manual_flag == A2D_MANUAL_TOP)
    {
        infonode = container_of(a2d_info.w3_displayed_list_head, infonode_t, listnode);
        if ((infonode->g_store_index - 1) < 0) {
            TI("It's at the top now.");
            RVoid();
        }

        index = (infonode->g_store_index - 1);
        ds = strore_frame_addr_array[index];

        a2d_info.analysis_status_flag = A2D_ANALYSISING;

        node = nd_dll_takeout_from_tail(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail);

        infonode = container_of(node, infonode_t, listnode);
        //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
        analysis_recover_w5node(&(a2d_info.w5_node_idle_list), &(infonode->w5head), &(infonode->w5tail));
        //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
        analysis_recover_l1l2node(
            &(a2d_info.l1l2_node_idle_list), &(infonode->l1l2head), &(infonode->l1l2tail),
            &(infonode->l1head), &(infonode->l1tail)
        );

        node->next = NULL;
        node->prev = NULL;
        infonode = container_of(node, infonode_t, listnode);
        infonode->g_store_index = index;

        analysis_network_frames((void *)infonode, &(ds->pkthdr), ds->data);

        nd_dll_intsert_into_head(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail, node);

        a2d_info.analysis_status_flag = A2D_ALALYSISED;
        a2d_info.w3_displayed_cur_node = a2d_info.w3_displayed_list_head;
        a2d_info.w3_displayed_cur_index = 0;
        a2d_info.is_manual_flag = A2D_MANUAL;
        return ;
    }
    else if (a2d_info.is_manual_flag == A2D_MANUAL_BOTTOM)
    {
        infonode = container_of(a2d_info.w3_displayed_list_tail, infonode_t, listnode);

        unsigned long tmp = 0;
        msgcomm_receive_status_value(&(d2c_flag_statistical.packages), tmp);
        if (infonode->g_store_index == (tmp - 1)) {
            TI("It's at the bottom now.");
            RVoid();
        }

        index = (infonode->g_store_index + 1);
        if (index == strore_frame_addr_array_index) 
        {
            c2a_shm_read_addr = (void *)C2A_COMM_ADDR_ALIGN(c2a_shm_read_addr);
            ds = (datastore_t *)c2a_shm_read_addr;
            strore_frame_addr_array[strore_frame_addr_array_index] = ds;
            c2a_shm_read_addr += (sizeof(struct pcap_pkthdr) + ds->pkthdr.len);
            strore_frame_addr_array_index++;
        }
        
        ds = strore_frame_addr_array[index];
        if (ds == NULL) 
        {
            TE("A fatal error occurred");
            exit(1);
        }

        a2d_info.analysis_status_flag = A2D_ANALYSISING;
        node = nd_dll_takeout_from_head(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail);

        infonode = container_of(node, infonode_t, listnode);
        //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
        analysis_recover_w5node(&(a2d_info.w5_node_idle_list), &(infonode->w5head), &(infonode->w5tail));
        //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
        analysis_recover_l1l2node(
            &(a2d_info.l1l2_node_idle_list), &(infonode->l1l2head), &(infonode->l1l2tail),
            &(infonode->l1head), &(infonode->l1tail)
        );

        node->next = NULL;
        node->prev = NULL;
        infonode = container_of(node, infonode_t, listnode);
        infonode->g_store_index = index;

        analysis_network_frames((void *)infonode, &(ds->pkthdr), ds->data);

        nd_dll_insert_into_tail(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail, node);

        a2d_info.analysis_status_flag = A2D_ALALYSISED;
        a2d_info.w3_displayed_cur_node = a2d_info.w3_displayed_list_tail;
        a2d_info.w3_displayed_cur_index = a2d_info.w3_displayed_cur_node_nums - 1;
        a2d_info.is_manual_flag = A2D_MANUAL;
        return ;
    }

    //nd_delay_microsecond(0, 2000000);
    return ;
}


/**
 * @brief
 *  fill in basic information
 * @memberof infonode
 *  nodes to be filled
 * @memberof h
 *  struct pcap_pkthdr pointer
 */
void analysis_fill_basic_info(void *infonode, const struct pcap_pkthdr *h)
{
    TC("Called { %s(%p, %p)", __func__, infonode, h);

    if (!infonode || !h) 
    {
        TE("param is error, infonode: %p, h: %p", infonode, h);
        abort();
    }

    int i = 0;
    nd_dll_t * node = NULL;
    l1l2_node_t * su = NULL, * l1l2 = NULL;

    infonode_t *ifn = (infonode_t *)infonode;

    for (i = 0; i < BASIC_INFO_TOTAL_NUMS; i++)
    {
        node = nd_dll_takeout_from_head_s(&(a2d_info.l1l2_node_idle_list));
        if (!node) {
            TE("fatal logic error; node: %p; a2d_info.l1l2_node_idle_list: %p", node, a2d_info.l1l2_node_idle_list);
            exit(1);
        }

        l1l2 = container_of(node, l1l2_node_t, l1l2node);

        switch (i)
        {
            case BASIC_INFO_L1_TITLE:
                su = l1l2;
                l1l2->superior = NULL;
                l1l2->level = 1;
                l1l2->isexpand = 1;
                memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
                sprintf(l1l2->content, BASIC_INFO_FORMAT, BASIC_INFO_CONTENT);
                nd_dll_insert_into_tail(&(ifn->l1head), &(ifn->l1tail), &(l1l2->l1node));
                break;
            case BASIC_INFO_L2_FRAME_NUMBER:
                l1l2->superior = su;
                l1l2->level = 2;
                l1l2->isexpand = 0;
                memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
                sprintf(l1l2->content, BASIC_INFO_SUB_SEQNUM, (ifn->g_store_index + 1));
                break;
            case BASIC_INFO_L2_ARRIVE_TIME:
                l1l2->superior = su;
                l1l2->level = 2;
                l1l2->isexpand = 0;
                memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
                #define BASIC_INFO_INVALIDTIMESTAMP "1970-01-01 00:00:00.000000"
                struct tm *tm = tm = localtime(&(h->ts.tv_sec));
                if (!tm) {
                    TE("the capture frame time is wrong");
                    sprintf(l1l2->content, BASIC_INFO_SUB_ARRIVE_TIME, BASIC_INFO_INVALIDTIMESTAMP);
                    break;
                }
                if (strftime(l1l2->content, L1L2NODE_CONTENT_LENGTH, "%Y-%m-%d %H:%M:%S", tm) == 0) {
                    TE("time conversion error");
                    sprintf(l1l2->content, BASIC_INFO_SUB_ARRIVE_TIME, BASIC_INFO_INVALIDTIMESTAMP);
                    break;
                }
                sprintf((l1l2->content + strlen(l1l2->content)), ".%06u", (unsigned)(h->ts.tv_usec));
                break;
            case BASIC_INFO_L2_FRAME_LENGTH:
                l1l2->superior = su;
                l1l2->level = 2;
                l1l2->isexpand = 0;
                memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
                sprintf(l1l2->content, BASIC_INFO_SUB_FRAME_LENGTH, h->len);
                break;
            case BASIC_INFO_L2_CAPTURE_LENGTH:
                l1l2->superior = su;
                l1l2->level = 2;
                l1l2->isexpand = 0;
                memset(l1l2->content, 0, L1L2NODE_CONTENT_LENGTH);
                sprintf(l1l2->content, BASIC_INFO_SUB_CAPTURE_LENGTH, h->caplen);
                break;
        }

        l1l2->byte_end = 0;
        l1l2->byte_start = 0;
        nd_dll_insert_into_tail(&(ifn->l1l2head), &(ifn->l1l2tail), &(l1l2->l1l2node));
    }

    RVoid();
}


/**
 * @brief determine whether it is a graphic
 */
#define ND_ASCII_ISGRAPH(c) ((c) > 0x20 && (c) <= 0x7E)

/**
 * @brief
 *  fill window 5 display content
 * @param infonode
 *  nodes to be filled
 * @param sp
 *  network frame raw data
 * @param caplen
 *  network frame capture length
 */
void analysis_fill_w5_content(void *infonode, const u_char *sp, u_int caplen)
{
    TC("Called { %s(%p, %p, %u)", __func__, infonode, sp, caplen);

    if (!infonode || !sp || (caplen == 0) || (caplen > 0x100000/*0xFFFF*/)) {
        TE("param is error, infonode: %p, sp: %p, caplen: %u [must less than 0xFFFF]", infonode, sp, caplen);
        abort();
    }

    u_int i;
    u_int s1, s2;
    u_int nshorts;
    char hexstuff[HEXDUMP_SHORTS_PER_LINE * HEXDUMP_HEXSTUFF_PER_SHORT + 1], *hsp;
    char asciistuff[ASCII_LINELENGTH + 1], *asp;

    u_int oset = 0;
    u_int length = caplen;
    u_int startindex = 0;
    w5_node_t * w5 = NULL;
    nd_dll_t * node = NULL;

    nshorts = length / sizeof(u_short);
    i = 0;
    hsp = hexstuff;
    asp = asciistuff;

    u_char * cp = (u_char *)sp;
    infonode_t *ifn = (infonode_t *)infonode;
    
    while (nshorts != 0)
    {
        s1 = (uint8_t)(*(cp)); 
        cp++;
        s2 = (uint8_t)(*(cp));
        cp++;
        (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
                       " %02x%02x", s1, s2);
        hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
        *(asp++) = (char)(ND_ASCII_ISGRAPH(s1) ? s1 : '.');
        *(asp++) = (char)(ND_ASCII_ISGRAPH(s2) ? s2 : '.');
        i++;
        if (i >= HEXDUMP_SHORTS_PER_LINE)
        {
            node = nd_dll_takeout_from_head_s(&(a2d_info.w5_node_idle_list));
            if (!node) {
                TE("fatal logic error; node: %p; a2d_info.w5_node_idle_list: %p", node, a2d_info.w5_node_idle_list);
                abort();
            }
            w5 = container_of(node, w5_node_t, w5node);
            *hsp = *asp = '\0';

            (void)snprintf(w5->content, W5NODE_CONTENT_LENGTH,
                           "0x%04x:   %-*s   %-*s",
                           oset, HEXDUMP_HEXSTUFF_PER_LINE, hexstuff, HEXDUMP_BYTES_PER_LINE, asciistuff);

            w5->startindex = startindex;
            w5->endindex = startindex + i * 2 - 1;
            startindex += i * 2;

            i = 0;
            hsp = hexstuff;
            asp = asciistuff;
            oset += HEXDUMP_BYTES_PER_LINE;
            nd_dll_insert_into_tail(&(ifn->w5head), &(ifn->w5tail), &(w5->w5node));
        }
        nshorts--;
    }

    i =  i * 2;

    if (length & 1)
    {
        s1 = (uint8_t)(*(cp));
        cp++;
        (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
                       " %02x", s1);
        hsp += 3;
        *(asp++) = (char)(ND_ASCII_ISGRAPH(s1) ? s1 : '.');
        ++i;
    }
    if (i > 0)
    {
        node = nd_dll_takeout_from_head_s(&(a2d_info.w5_node_idle_list));
        if (!node) {
            TE("fatal logic error; node: %p; a2d_info.w5_node_idle_list: %p", node, a2d_info.w5_node_idle_list);
            abort();
        }
        w5 = container_of(node, w5_node_t, w5node);
        *hsp = *asp = '\0';

        (void)snprintf(w5->content, W5NODE_CONTENT_LENGTH,
                       "0x%04x:   %-*s   %-*s",
                       oset, HEXDUMP_HEXSTUFF_PER_LINE, hexstuff, HEXDUMP_BYTES_PER_LINE, asciistuff);

        w5->startindex = startindex;
        w5->endindex = startindex + i - 1;

        nd_dll_insert_into_tail(&(ifn->w5head), &(ifn->w5tail), &(w5->w5node));
    }
    
    RVoid();
}

/**
 * @brief
 *  Define ndo global variables
 *  Load in the function analysis_network_frames
 *  In header.h declaration
 */
ndo_t * ndo = NULL;

/**
 * @brief
 *  Parsing network frames
 * @memberof infonode
 *  nodes to be filled
 * @memberof header
 *  struct pcap_pkthdr pointer
 * @memberof packet
 *  network frame data
 */
void analysis_network_frames(void *infonode, const struct pcap_pkthdr *h, const u_char *sp)
{

    TC("Called { %s(%p, %p)", __func__, h, sp);

    ndo = ((ndo_t *)(&(d2c_comm.d2c_ndo)));

    infonode_t * ifn = (infonode_t *)infonode;

    analysis_fill_basic_info(infonode, h);

    analysis_fill_w5_content(infonode, sp, h->caplen);

    analysis_ts_print(ndo, &(h->ts), ifn->timestamp);

    ndo->ndo_snapend = sp + h->caplen;
    ndo->ndo_packetp = sp;
    ndo->ndo_protocol = "";
    ndo->ndo_ll_hdr_len = 0;
    ndo->ndo_packet_info_stack = NULL;

    switch (setjmp(ndo->ndo_early_end))
    {
        case 0:
            (ndo->ndo_if_printer)(ndo, infonode, h, sp);
            break;
        case ND_TRUNCATED:
            ndo->ndo_ll_hdr_len = 0;
            TE("Packet truncated");
            break;
    }

    RVoid();
}


/**
 * @brief
 *  Get infonode node pointer
 * @return
 *  Returns the obtained node pointer if successful.
 *  Returns NULL if failed
 */
infonode_t *analysis_get_infonode (void)
{

    TC("Called { %s (void)", __func__);

    nd_dll_t *tmp = nd_dll_takeout_from_head_s(&(a2d_info.info_node_idle_list));

    infonode_t * infonode = container_of(tmp, infonode_t, listnode);

    infonode->idx = 0;

    RVoidPtr(infonode);
}


/**
 * @brief
 *  Put in infonode to finlist
 * @memberof infonode
 *  Waiting for the node element to be put into finlist
 */
void analysis_putin_infonode (infonode_t *infonode)
{

    TC("Called { %s (%p)", __func__, infonode);

    if (!a2d_info.analysis_finished_list_head && !a2d_info.analysis_finished_list_tail)
    {
        nd_dll_intsert_into_head(&(a2d_info.analysis_finished_list_head), 
                    &(a2d_info.analysis_finished_list_tail), &(infonode->listnode));
        a2d_info.analysis_finished_list_tail = a2d_info.analysis_finished_list_head;
        RVoid();
    }

    nd_dll_insert_into_tail(&(a2d_info.analysis_finished_list_head), 
                    &(a2d_info.analysis_finished_list_tail), &(infonode->listnode));

    RVoid();
}


/**
 * @brief
 *  Take out the parsed DLL and put it into the display DLL;
 *  if the display DLL is full,
 *  take out some elements from the DLL header,
 *  put them into the free DLL,
 *  and then take out the parsed DLL and put it into the display DLL;
 *  if the display DLL is not full,
 *  take out the parsed DLL and put it into the display DLL
 *
 *  Update to show the number of elements in the DLL
 *  Specifies that the element currently displayed is not the last element of the DLL
 * @return
 *  Returns the number of entries added to the display DLL
 */
int analysis_put_node_into_display_dll (void)
{

    TC("Called { %s (void)", __func__);

    int i = 0;
    nd_dll_t * node = NULL;
    unsigned short ret = 0, min = 0;

    if (!a2d_info.analysis_finished_node_nums)
    {
        RInt(ret);
    }

    if (a2d_info.w3_displayed_cur_node_nums == 0)
    {
        min = MINIMUM(a2d_info.analysis_finished_node_nums, a2d_info.w3_displayed_max_lines);
        for (i = 0; i < min; i++) {
            node = nd_dll_takeout_from_head(&(a2d_info.analysis_finished_list_head), &(a2d_info.analysis_finished_list_tail));
            if (!a2d_info.analysis_finished_list_head) {
                a2d_info.analysis_finished_list_tail = NULL;
            }
            if (i == 0) {
                nd_dll_intsert_into_head(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail, node);
                a2d_info.w3_displayed_list_tail = a2d_info.w3_displayed_list_head;
            }
            else {
                nd_dll_insert_into_tail(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail, node);
            }
        }
        a2d_info.w3_displayed_cur_node_nums += min;
    }
    else if (a2d_info.w3_displayed_cur_node_nums < a2d_info.w3_displayed_max_lines)
    {
        min = MINIMUM(a2d_info.analysis_finished_node_nums, (a2d_info.w3_displayed_max_lines - a2d_info.w3_displayed_cur_node_nums));
        
        for (i = 0; i < min; i++) {
            node = nd_dll_takeout_from_head(&(a2d_info.analysis_finished_list_head), &(a2d_info.analysis_finished_list_tail));
            if (!a2d_info.analysis_finished_list_head) {
                a2d_info.analysis_finished_list_tail = NULL;
            }
            nd_dll_insert_into_tail(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail, node);
        }
        a2d_info.w3_displayed_cur_node_nums += min;
    }
    else if (a2d_info.w3_displayed_cur_node_nums == a2d_info.w3_displayed_max_lines)
    {
        min = MINIMUM(A2D_PUTIN_DISPLAY_DLL_MAX_NUMS, a2d_info.analysis_finished_node_nums);
        for (i = 0; i < min; i++) 
        {
            node = nd_dll_takeout_from_head(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail);

            infonode_t * infonode = container_of(node, infonode_t, listnode);

            //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);
            analysis_recover_w5node(&(a2d_info.w5_node_idle_list), &(infonode->w5head), &(infonode->w5tail));
            //analysis_count_w5node_nums(a2d_info.w5_node_idle_list);

            analysis_recover_l1l2node(
                &(a2d_info.l1l2_node_idle_list), &(infonode->l1l2head), &(infonode->l1l2tail),
                &(infonode->l1head), &(infonode->l1tail)
            );

            nd_dll_intsert_into_head_s(&(a2d_info.info_node_idle_list), node);
            node = nd_dll_takeout_from_head(&(a2d_info.analysis_finished_list_head), &(a2d_info.analysis_finished_list_tail));
            if (!a2d_info.analysis_finished_list_head) {
                a2d_info.analysis_finished_list_tail = NULL;
            }
            nd_dll_insert_into_tail(&a2d_info.w3_displayed_list_head, &a2d_info.w3_displayed_list_tail, node);
        }
    }
    else{
        TE("a fatal error occurred");
        exit(1);
    }

    a2d_info.analysis_finished_node_nums -= min;
    a2d_info.w3_displayed_cur_node = a2d_info.w3_displayed_list_tail;
    a2d_info.w3_displayed_cur_index = a2d_info.w3_displayed_cur_node_nums - 1;

    RInt(ret);
}


/**
 * @brief
 *  count the number of l1l2nodes
 */
void analysis_count_l1l2node_nums (nd_dll_t * idlehead)
{
    unsigned int count = 0;

    nd_dll_t * tmp = idlehead;

    while (tmp) 
    {
        tmp = tmp->next;
        count++;
    }

    TI("l1l2node nums: %u", count);

    return ;
}


/**
 * @brief
 *   count the number of w5nodes
 */
void analysis_count_w5node_nums (nd_dll_t *idlehead)
{
    unsigned int count = 0;

    nd_dll_t *tmp = idlehead;

    while (tmp)
    {
        tmp = tmp->next;
        count++;
    }

    TI("w5node nums: %u", count);

    return;
}


/**
 * @brief
 *  recover l1l2node
 * @param idlehead
 *  l1l2node idle list head
 * @param head
 *  head pointer to be recycled
 * @param tail
 *  tail pointer to be recycled
 * @param l1head
 *  l1head pointer to be recycled
 * @param l1tail
 *  l1tail pointer to be recycled
 */
void analysis_recover_l1l2node(
    nd_dll_t ** idlehead, nd_dll_t ** head, nd_dll_t ** tail, nd_dll_t ** l1head, nd_dll_t ** l1tail)
{

    TC("Called { %s(%p, %p, %p, %p, %p)", __func__, idlehead, head, tail, l1head, l1tail);

    if (!idlehead || !(*idlehead) || !head || !tail || !l1head || !l1tail) {
        TE("there is a case where the parameter is NULL"
            "(idlehead: %p, *idlehead: %p, head: %p, tail: %p, l1head: %p, l1tail: %p)", 
            idlehead, *idlehead, head, tail, l1head, l1tail);
        exit(1);
    }

    if (!(*idlehead)) {
        TE("fatal logic error; *idlehead: %p", *idlehead);
        exit(1);
    } 

    if ((!(*head) && *tail) || (*head && !(*tail)) || 
        (!(*l1head) && *l1tail) || (*l1head && !(*l1tail)))
    {
        TE("fatal logic error; *head: %p; *tail: %p; l1head: %p; l1tail: %p", 
            *head, *tail, *l1head, *l1tail);
        exit(1);
    }

    if (!(*head) && !(*tail) && !(*l1head) && !(*l1tail)) {
        TI("don't need recover l1l2node");
        RVoid();
    }

    nd_dll_insert_into_head_multiple(idlehead, *head, *tail);

    *head = NULL; *tail = NULL;
    *l1head = NULL; *l1tail = NULL;

    RVoid();
}


/**
 * @brief
 *  recover w5node
 * @param idlehead
 *  w5node idle list head
 * @param head
 *  head pointer to be recycled
 * @param tail
 *  tail pointer to be recycled
 */
void analysis_recover_w5node(nd_dll_t ** idlehead, nd_dll_t ** head, nd_dll_t ** tail)
{
    TC("Called { %s(%p, %p, %p)", __func__, idlehead, head, tail);

    if (!idlehead || !head || !tail) {
        TE("there is a case where the parameter is NULL"
           "(idlehead: %p, head: %p, tail: %p)", idlehead, head, tail);
        exit(1);
    }

    if (!(*idlehead)) {
        TE("fatal logic error; *idlehead: %p", *idlehead);
        exit(1);
    }

    if ((!(*head) && *tail) || (*head && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    if (!(*head) && !(*tail)) {
        TI("don't need recover w5node");
        RVoid();
    }

    nd_dll_insert_into_head_multiple(idlehead, *head, *tail);

    *head = NULL; *tail = NULL;

    RVoid();
}