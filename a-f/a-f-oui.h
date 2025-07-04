
#ifndef __AF_OUI_H__
#define __AF_OUI_H__

extern const struct tok oui_values[];

#define OUI_ENCAP_ETHER 0x000000       /* encapsulated Ethernet */
#define OUI_CISCO 0x00000c             /* Cisco protocols */
#define OUI_IANA 0x00005E              /* IANA */
#define OUI_NORTEL 0x000081            /* Nortel SONMP */
#define OUI_CISCO_90 0x0000f8          /* Cisco bridging */
#define OUI_RFC2684 0x0080c2           /* RFC 2427/2684 bridged Ethernet */
#define OUI_ATM_FORUM 0x00A03E         /* ATM Forum */
#define OUI_CABLE_BPDU 0x00E02F        /* DOCSIS spanning tree BPDU */
#define OUI_APPLETALK 0x080007         /* Appletalk */
#define OUI_JUNIPER 0x009069           /* Juniper */
#define OUI_HP 0x080009                /* Hewlett-Packard */
#define OUI_IEEE_8021_PRIVATE 0x0080c2 /* IEEE 802.1 Organisation Specific - Annex F */
#define OUI_IEEE_8023_PRIVATE 0x00120f /* IEEE 802.3 Organisation Specific - Annex G */
#define OUI_TIA 0x0012bb               /* TIA - Telecommunications Industry Association - ANSI/TIA-1057- 2006 */
#define OUI_DCBX 0x001B21              /* DCBX */
#define OUI_NICIRA 0x002320            /* Nicira Networks */
#define OUI_BSN 0x5c16c7               /* Big Switch Networks */
#define OUI_VELLO 0xb0d2f5             /* Vello Systems */
#define OUI_HP2 0x002481               /* HP too */
#define OUI_HPLABS 0x0004ea            /* HP-Labs */
#define OUI_INFOBLOX 0x748771          /* Infoblox Inc */
#define OUI_ONLAB 0xa42305             /* Open Networking Lab */
#define OUI_FREESCALE 0x00049f         /* Freescale */
#define OUI_NETRONOME 0x0015ad         /* Netronome */
#define OUI_BROADCOM 0x001018          /* Broadcom */
#define OUI_PMC_SIERRA 0x00e004        /* PMC-Sierra */
#define OUI_ERICSSON 0xd0f0db          /* Ericsson */

#endif //__AF_OUI_H__