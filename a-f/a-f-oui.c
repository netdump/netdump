
#include "ndo.h"
#include "a-f-oui.h"

/* FIXME complete OUI list using a script */

const struct tok oui_values[] = {
    {OUI_ENCAP_ETHER, "Ethernet"},
    {OUI_CISCO, "Cisco"},
    {OUI_IANA, "IANA"},
    {OUI_NORTEL, "Nortel Networks SONMP"},
    {OUI_CISCO_90, "Cisco bridged"},
    {OUI_RFC2684, "Ethernet bridged"},
    {OUI_ATM_FORUM, "ATM Forum"},
    {OUI_CABLE_BPDU, "DOCSIS Spanning Tree"},
    {OUI_APPLETALK, "Appletalk"},
    {OUI_JUNIPER, "Juniper"},
    {OUI_HP, "Hewlett-Packard"},
    {OUI_IEEE_8021_PRIVATE, "IEEE 802.1 Private"},
    {OUI_IEEE_8023_PRIVATE, "IEEE 802.3 Private"},
    {OUI_TIA, "ANSI/TIA"},
    {OUI_DCBX, "DCBX"},
    {OUI_NICIRA, "Nicira Networks"},
    {OUI_BSN, "Big Switch Networks"},
    {OUI_VELLO, "Vello Systems"},
    {OUI_HP2, "HP"},
    {OUI_HPLABS, "HP-Labs"},
    {OUI_INFOBLOX, "Infoblox Inc"},
    {OUI_ONLAB, "Open Networking Lab"},
    {OUI_FREESCALE, "Freescale"},
    {OUI_NETRONOME, "Netronome"},
    {OUI_BROADCOM, "Broadcom"},
    {OUI_PMC_SIERRA, "PMC-Sierra"},
    {OUI_ERICSSON, "Ericsson"},
    {0, NULL}
};
