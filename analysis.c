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
    TI("%s %02x:%02x:%02x:%02x:%02x:%02x", label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const unsigned char *payload, int len)
{
    char buffer[96] = {0};
    TI("Payload (first %d bytes): ", len);
    for (int i = 0; i < len; i++)
    {
        sprintf(buffer + strlen(buffer), "%02x ", payload[i]);
    }
    TI("%s", buffer);
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
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

        TI("Protocol: IPv4");
        TI("Source IP: %s", inet_ntoa(src_ip));
        TI("Destination IP: %s", inet_ntoa(dst_ip));

        ip_header_len = ip_header->ihl * 4;
    }
    else if (eth_type == ETHERTYPE_IPV6)
    { // IPv6
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, sizeof(dst_ip));

        TI("Protocol: IPv6");
        TI("Source IP: %s", src_ip);
        TI("Destination IP: %s", dst_ip);

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
        TI("Source Port: %u", ntohs(tcp_header->source));
        TI("Destination Port: %u", ntohs(tcp_header->dest));

        // 计算 TCP 负载起始位置
        int tcp_header_len = tcp_header->doff * 4;
        const unsigned char *payload = transport_header + tcp_header_len;
        int payload_len = header->caplen - (payload - packet);

        print_payload(payload, payload_len > 16 ? 16 : payload_len);
    }
    else if (protocol == IPPROTO_UDP)
    { // UDP
        struct udphdr *udp_header = (struct udphdr *)transport_header;
        TI("Source Port: %u", ntohs(udp_header->source));
        TI("Destination Port: %u", ntohs(udp_header->dest));

        // 计算 UDP 负载起始位置
        const unsigned char *payload = transport_header + sizeof(struct udphdr);
        int payload_len = header->caplen - (payload - packet);

        print_payload(payload, payload_len > 16 ? 16 : payload_len);
    }

    return;
}

#endif

/**
 * @brief 
 *  The main loop of the packet parsing process
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int analysis_loop (void) {

    TC("Called { %s(void)", __func__);

    static unsigned long long count = 0, tmp;

    for (;;) 
    {
        tmp = __sync_fetch_and_add(msgcomm_st_NOpackages, 0);
        if (tmp == count || tmp == 0 || count > tmp) 
        {
            if (count > tmp) 
            {
                count = 0;
            }
            nd_delay_microsecond(1, 1000);
            continue;
        }

        #if 1
        G_ctoa_shm_mem_rp = (void *)CTOACOMM_ADDR_ALIGN(G_ctoa_shm_mem_rp);
        datastore_t *ds = (datastore_t *)G_ctoa_shm_mem_rp;

        TI("pre rp %p", ds);

        struct pcap_pkthdr * pkthdr = &(ds->pkthdr);
        TI("pkthdr->ts.tv_sec: %lu, pkthdr->ts.tv_usec: %lu, pkthdr->caplen: %u, pkthdr->len: %u", 
                pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len);

        packet_handler(NULL, NULL, ds->data);

        G_ctoa_shm_mem_rp += (sizeof(struct pcap_pkthdr) + ds->pkthdr.len);

        TI("after rp: %p; sizeof(struct pcap_pkthdr): %lu; ds->pkthdr.len: %u", G_ctoa_shm_mem_rp, sizeof(struct pcap_pkthdr), ds->pkthdr.len);

        count++;
        #endif
    }

    RInt(ND_OK);
}