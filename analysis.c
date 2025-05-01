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

    __builtin_prefetch((void *)CTOACOMM_ADDR_ALIGN(G_ctoa_shm_mem_rp), 0, 3);

    for (;;) 
    {
        if (!ATOD_DISPLAY_MAX_LINES)
        {
            nd_delay_microsecond(0, 1000);
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
 * @brief The Code for debug
 */
#if 1
void print_mac(const char *label, const unsigned char *mac)
{
    //TI("%s %02x:%02x:%02x:%02x:%02x:%02x", label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const unsigned char *payload, int len)
{
    char buffer[96] = {0};
    //TI("Payload (first %d bytes): ", len);
    for (int i = 0; i < len; i++)
    {
        sprintf(buffer + strlen(buffer), "%02x ", payload[i]);
    }
    //TI("%s", buffer);
}


void packet_handler(infonode_t * infonode, const struct pcap_pkthdr *header, const unsigned char *packet)
{

    //TC("Called { %s(%p, %p, %p)", __func__, infonode, header, packet);

    struct tm * tm_info = localtime(&(header->ts.tv_sec));
    memset(infonode->timestamp, 0, sizeof(infonode->timestamp));
    snprintf(infonode->timestamp, sizeof(infonode->timestamp), "%02d:%02d:%02d.%06ld",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, header->ts.tv_usec);

    //TI("infonode: %p; infonode->timestamp: %s", infonode, infonode->timestamp);

    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t eth_type = ntohs(eth_header->ether_type);
    int ip_header_len = 0;

    print_mac("Source MAC:", eth_header->ether_shost);
    print_mac("Destination MAC:", eth_header->ether_dhost);

    if (eth_type == ETHERTYPE_IP)
    { // IPv4
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = ip_header->saddr;
        dst_ip.s_addr = ip_header->daddr;

        //TI("Protocol: IPv4");
        //TI("Source IP: %s", inet_ntoa(src_ip));
        memset(infonode->srcaddr, 0, sizeof(infonode->srcaddr));
        snprintf(infonode->srcaddr, sizeof(infonode->srcaddr), "%s", inet_ntoa(src_ip));
        //TI("Destination IP: %s", inet_ntoa(dst_ip));
        memset(infonode->dstaddr, 0, sizeof(infonode->srcaddr));
        snprintf(infonode->dstaddr, sizeof(infonode->dstaddr), "%s", inet_ntoa(dst_ip));

        ip_header_len = ip_header->ihl * 4;
    }
    else if (eth_type == ETHERTYPE_IPV6)
    { // IPv6
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, sizeof(dst_ip));

        //TI("Protocol: IPv6");
        //TI("Source IP: %s", src_ip);
        //TI("Destination IP: %s", dst_ip);

        ip_header_len = sizeof(struct ip6_hdr);
    }
    else if (eth_type == ETHERTYPE_ARP)
    { // ARP
        TI("Protocol: ARP (Skipping IP and ports)");
        return;
    }
    else
    {
        TI("Unknown protocol: 0x%04x", eth_type);
        return;
    }

    // 计算 IP 头部后的数据偏移
    const unsigned char *transport_header = packet + sizeof(struct ether_header) + ip_header_len;
    uint8_t protocol = eth_type == ETHERTYPE_IP ? ((struct iphdr *)(packet + sizeof(struct ether_header)))->protocol : 0;

    if (protocol == IPPROTO_TCP)
    { // TCP
        struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
        //TI("Source Port: %u", ntohs(tcp_header->source));
        //TI("Destination Port: %u", ntohs(tcp_header->dest));
        snprintf(infonode->srcaddr + strlen(infonode->srcaddr), sizeof(infonode->srcaddr) - strlen(infonode->srcaddr), ".%u", ntohs(tcp_header->source));
        snprintf(infonode->dstaddr + strlen(infonode->dstaddr), sizeof(infonode->dstaddr) - strlen(infonode->dstaddr), ".%u", ntohs(tcp_header->dest));
        //TI("infonode->srcaddr: %s; infonode->dstaddr: %s", infonode->srcaddr, infonode->dstaddr);
        memset(infonode->protocol, 0, sizeof(infonode->protocol));
        snprintf(infonode->protocol, sizeof(infonode->protocol), "%s", "tcp");
        // 计算 TCP 负载起始位置
        int tcp_header_len = tcp_header->doff * 4;
        const unsigned char *payload = transport_header + tcp_header_len;
        int payload_len = header->caplen - (payload - packet);
        memset(infonode->length, 0, sizeof(infonode->length));
        snprintf(infonode->length, sizeof(infonode->length), "%u", payload_len);

        print_payload(payload, payload_len > 16 ? 16 : payload_len);
    }
    else if (protocol == IPPROTO_UDP)
    { // UDP
        struct udphdr *udp_header = (struct udphdr *)transport_header;
        //TI("Source Port: %u", ntohs(udp_header->source));
        //TI("Destination Port: %u", ntohs(udp_header->dest));
        snprintf(infonode->srcaddr + strlen(infonode->srcaddr), sizeof(infonode->srcaddr) - strlen(infonode->srcaddr), ".%u", ntohs(udp_header->source));
        snprintf(infonode->dstaddr + strlen(infonode->dstaddr), sizeof(infonode->dstaddr) - strlen(infonode->dstaddr), ".%u", ntohs(udp_header->dest));
        memset(infonode->protocol, 0, sizeof(infonode->protocol));
        snprintf(infonode->protocol, sizeof(infonode->protocol), "%s", "udp");

        // 计算 UDP 负载起始位置
        const unsigned char *payload = transport_header + sizeof(struct udphdr);
        int payload_len = header->caplen - (payload - packet);
        memset(infonode->length, 0, sizeof(infonode->length));
        snprintf(infonode->length, sizeof(infonode->length), "%u", payload_len);

        print_payload(payload, payload_len > 16 ? 16 : payload_len);
    }

    snprintf(infonode->brief, sizeof(infonode->brief), "%s", "Test output position");

    //RVoid();
    return ;
}

#endif

/**
 * @brief
 *  Store captured network frame pointers in order
 */
#define ARRAY_LENGTH        1048576
datastore_t * G_frame_ptr_array[ARRAY_LENGTH] = {NULL};
static unsigned long Gindex = 0;


/**
 * @brief 
 *  The main loop of the packet parsing process
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int analysis_loop (void) {

    TC("Called { %s(void)", __func__);

    for (;;) 
    {
        if (msgcomm_st_cppc)
        {
            if (G_dtoainfo->flag[0])
                analysis_manual_mode();
            else
                analysis_no_manual_mode();
        }
        else 
        {
            nd_delay_microsecond(1, 1000);
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
    unsigned long tmp = __sync_fetch_and_add(msgcomm_st_NOpackages, 0);
    if (tmp == Gindex || tmp == 0 || Gindex > tmp)
    {
        if (Gindex > tmp)
        {
            memset(G_frame_ptr_array, 0, (ARRAY_LENGTH * sizeof(void *)));
            atodcomm_init_dtoainfo_to_zero();
            atodcomm_init_infonode_list();
            G_ctoa_shm_mem_rp = CTOACOMM_SHM_BASEADDR;
            Gindex = 0;
        }
        else {
            nd_delay_microsecond(1, 1000);
        }
        return ;
    }

    infonode_t * infonode = analysis_get_infonode();
    if (infonode)
    {
        G_ctoa_shm_mem_rp = (void *)CTOACOMM_ADDR_ALIGN(G_ctoa_shm_mem_rp);

        datastore_t *ds = (datastore_t *)G_ctoa_shm_mem_rp;

        //packet_handler(infonode, &(ds->pkthdr), ds->data);
        analysis_network_frames((void *)infonode, &(ds->pkthdr), ds->data);

        G_frame_ptr_array[Gindex] = ds;

        infonode->g_store_index = Gindex;

        G_ctoa_shm_mem_rp += (sizeof(struct pcap_pkthdr) + ds->pkthdr.len);

        Gindex++;

        analysis_putin_infonode(infonode);

        ATOD_FINISH_DLL_NUMS++;
    }

    ATOD_ANALYSIS_VAR_FLAG = ATOD_ANALYSISING;

    if (DTOA_DISPLAY_VAR_FLAG == DTOA_DISPLAYED)
        analysis_put_node_into_display_dll();

    ATOD_ANALYSIS_VAR_FLAG = ATOD_ALALYSISED;

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

    if (ATOD_FINISH_DLL_NUMS) {
        for (i = 0; i < ATOD_FINISH_DLL_NUMS; i++)
        {
            node = nd_dll_takeout_from_tail(&ATOD_FINISH_DLL_TAIL);
            nd_dll_intsert_into_head(&ATOD_IDLE_DLL, node);
        }
        ATOD_FINISH_DLL_NUMS = 0;
        if (!ATOD_FINISH_DLL_TAIL)
            ATOD_FINISH_DLL_HEAD = NULL;
    }

    if (DTOA_ISOR_MANUAL_VAR_FLAG == DTOA_MANUAL_TOP)
    {
        infonode = container_of(ATOD_DISPLAY_DLL_HEAD, infonode_t, listnode);
        if ((infonode->g_store_index - 1) < 0) {
            TI("It's at the top now.");
            RVoid();
        }
        index = (infonode->g_store_index - 1);
        ds = G_frame_ptr_array[index];
        node = nd_dll_takeout_from_tail(&ATOD_DISPLAY_DLL_TAIL);
        node->next = NULL;
        node->prev = NULL;
        infonode = container_of(node, infonode_t, listnode);
        infonode->g_store_index = index;
        //packet_handler(infonode, &(ds->pkthdr), ds->data);
        analysis_network_frames((void *)infonode, &(ds->pkthdr), ds->data);
        nd_dll_intsert_into_head(&ATOD_DISPLAY_DLL_HEAD, node);
        ATOD_CUR_DISPLAY_LINE = ATOD_DISPLAY_DLL_HEAD;
        ATOD_CUR_DISPLAY_INDEX = 0;
        DTOA_ISOR_MANUAL_VAR_FLAG = DTOA_MANUAL;
    }
    else if (DTOA_ISOR_MANUAL_VAR_FLAG == DTOA_MANUAL_BOTTOM)
    {
        infonode = container_of(ATOD_DISPLAY_DLL_TAIL, infonode_t, listnode);
        unsigned long tmp = __sync_fetch_and_add(msgcomm_st_NOpackages, 0);
        if (infonode->g_store_index == (tmp - 1)) {
            TI("It's at the bottom now.");
            RVoid();
        }

        index = (infonode->g_store_index + 1);
        if (index == Gindex) 
        {
            G_ctoa_shm_mem_rp = (void *)CTOACOMM_ADDR_ALIGN(G_ctoa_shm_mem_rp);
            ds = (datastore_t *)G_ctoa_shm_mem_rp;
            G_frame_ptr_array[Gindex] = ds;
            G_ctoa_shm_mem_rp += (sizeof(struct pcap_pkthdr) + ds->pkthdr.len);
            Gindex++;
        }
        
        ds = G_frame_ptr_array[index];
        if (ds == NULL) 
        {
            TE("A fatal error occurred");
            exit(1);
        }

        node = nd_dll_takeout_from_head(&ATOD_DISPLAY_DLL_HEAD);
        node->next = NULL;
        node->prev = NULL;
        infonode = container_of(node, infonode_t, listnode);
        infonode->g_store_index = index;
        //packet_handler(infonode, &(ds->pkthdr), ds->data);
        analysis_network_frames((void *)infonode, &(ds->pkthdr), ds->data);
        nd_dll_insert_into_tail(&ATOD_DISPLAY_DLL_TAIL, node);
        ATOD_CUR_DISPLAY_LINE = ATOD_DISPLAY_DLL_TAIL;
        ATOD_CUR_DISPLAY_INDEX = ATOD_DISPLAY_DLL_NUMS - 1;
        DTOA_ISOR_MANUAL_VAR_FLAG = DTOA_MANUAL;
    }
   
    return ;
}


/**
 * @brief
 *  Parsing network frames
 * @memberof infonode
 *  
 * @memberof header
 *  struct pcap_pkthdr pointer
 * @memberof packet
 *  network frame data
 */
void analysis_network_frames(void *infonode, const struct pcap_pkthdr *h, const unsigned char *sp)
{

    TC("Called { %s(%p, %p)", __func__, h, sp);

    ndo_t *ndo = ((ndo_t *)(msgcomm_G_ndo));

    ndo->ndo_snapend = sp + h->caplen;
    ndo->ndo_packetp = sp;
    ndo->ndo_protocol = "";
    ndo->ndo_ll_hdr_len = 0;

    switch (setjmp(ndo->ndo_early_end))
    {
        case 0:
            (ndo->ndo_if_printer)(ndo, infonode, h, sp);
            break;
        case ND_TRUNCATED:
            //nd_print_trunc(ndo);
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

    nd_dll_t * tmp = nd_dll_takeout_from_head(&(G_dtoainfo->idlelist));

    infonode_t * infonode = container_of(tmp, infonode_t, listnode);

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

    if (!ATOD_FINISH_DLL_HEAD && !ATOD_FINISH_DLL_TAIL)
    {
        nd_dll_intsert_into_head(&ATOD_FINISH_DLL_HEAD, &(infonode->listnode));
        ATOD_FINISH_DLL_TAIL = ATOD_FINISH_DLL_HEAD;
        RVoid();
    }

    nd_dll_insert_into_tail(&ATOD_FINISH_DLL_TAIL, &(infonode->listnode));

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

    if (!ATOD_FINISH_DLL_NUMS)
    {
        RInt(ret);
    }

    if (ATOD_DISPLAY_DLL_NUMS == 0)
    {
        min = MINIMUM(ATOD_FINISH_DLL_NUMS, ATOD_DISPLAY_MAX_LINES);
        for (i = 0; i < min; i++) {
            node = nd_dll_takeout_from_head(&ATOD_FINISH_DLL_HEAD);
            if (!ATOD_FINISH_DLL_HEAD)
            {
                ATOD_FINISH_DLL_TAIL = NULL;
            }
            if (i == 0) {
                nd_dll_intsert_into_head(&ATOD_DISPLAY_DLL_HEAD, node);
                ATOD_DISPLAY_DLL_TAIL = ATOD_DISPLAY_DLL_HEAD;
            }
            else {
                nd_dll_insert_into_tail(&ATOD_DISPLAY_DLL_TAIL, node);
            }
        }
        ATOD_DISPLAY_DLL_NUMS += min;
    }
    else if (ATOD_DISPLAY_DLL_NUMS < ATOD_DISPLAY_MAX_LINES)
    {
        min = MINIMUM(ATOD_FINISH_DLL_NUMS, (ATOD_DISPLAY_MAX_LINES - ATOD_DISPLAY_DLL_NUMS));
        
        for (i = 0; i < min; i++) {
            node = nd_dll_takeout_from_head(&ATOD_FINISH_DLL_HEAD);
            if (!ATOD_FINISH_DLL_HEAD)
            {
                ATOD_FINISH_DLL_TAIL = NULL;
            }
            nd_dll_insert_into_tail(&ATOD_DISPLAY_DLL_TAIL, node);
        }
        ATOD_DISPLAY_DLL_NUMS += min;
    }
    else if (ATOD_DISPLAY_DLL_NUMS == ATOD_DISPLAY_MAX_LINES)
    {
        min = MINIMUM(ATOD_PUTIN_DISPLAY_DLL_MAX_NUMS, ATOD_FINISH_DLL_NUMS);
        for (i = 0; i < min; i++) 
        {
            node = nd_dll_takeout_from_head(&ATOD_DISPLAY_DLL_HEAD);
            nd_dll_intsert_into_head(&ATOD_IDLE_DLL, node);
            node = nd_dll_takeout_from_head(&ATOD_FINISH_DLL_HEAD);
            if (!ATOD_FINISH_DLL_HEAD)
            {
                ATOD_FINISH_DLL_TAIL = NULL;
            }
            nd_dll_insert_into_tail(&ATOD_DISPLAY_DLL_TAIL, node);
        }
    }
    else{
        TE("a fatal error occurred");
        exit(1);
    }

    ATOD_FINISH_DLL_NUMS -= min;
    ATOD_CUR_DISPLAY_LINE = ATOD_DISPLAY_DLL_TAIL;
    ATOD_CUR_DISPLAY_INDEX = ATOD_DISPLAY_DLL_NUMS - 1;

    RInt(ret);
}