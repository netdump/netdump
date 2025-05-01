
#include "header.h"


#ifdef DLT_JUNIPER_ES
void juniper_es_if_print(ndo_t *ndo, void *infondoe, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_CHDLC
void juniper_chdlc_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


/*
 *     ATM1 PIC cookie format
 *
 *     +-----+-------------------------+-------------------------------+
 *     |fmtid|     vc index            |  channel  ID                  |
 *     +-----+-------------------------+-------------------------------+
 */

#ifdef DLT_JUNIPER_ATM1
void juniper_atm1_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif

/*
 *     ATM2 PIC cookie format
 *
 *     +-------------------------------+---------+---+-----+-----------+
 *     |     channel ID                |  reserv |AAL| CCRQ| gap cnt   |
 *     +-------------------------------+---------+---+-----+-----------+
 */

#ifdef DLT_JUNIPER_ATM2
void juniper_atm2_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_ETHER
void juniper_ether_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_FRELAY
void juniper_frelay_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_GGSN
void juniper_ggsn_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_MFR
void juniper_mfr_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_MLFR
void juniper_mlfr_if_print(ndo_t *ndo, void *infondoe, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_MLPPP
void juniper_mlppp_if_print(ndo_t *ndo, void *infondoe, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_MONITOR
void juniper_monitor_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_PPP
void juniper_ppp_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_PPPOE_ATM
void juniper_pppoe_atm_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_PPPOE
void juniper_pppoe_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


#ifdef DLT_JUNIPER_SERVICES
void juniper_services_if_print(ndo_t *ndo, void *infonode, const struct pcap_pkthdr *h, const u_char *p)
{

    return ;
}
#endif


