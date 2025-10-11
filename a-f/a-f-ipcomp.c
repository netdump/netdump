/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: IP Payload Compression Protocol (IPComp) printer */

#include "ndo.h"
#include "header.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"

struct ipcomp
{
    nd_uint8_t comp_nxt;   /* Next Header */
    nd_uint8_t comp_flags; /* Length of data, in 32bit */
    nd_uint16_t comp_cpi;  /* Compression parameter index */
};

#define LAYER_4_IPCOMP_CONTENT              "IP Payload Compression Protocol: "
#define LAYER_4_IPCOMP_NXT                  "next header: %u (%s)"
#define LAYER_4_IPCOMP_FLAGS                "flags: %u"
#define LAYER_4_IPCOMP_CPI                  "compression parameter index(cpi): 0x%04x"

void ipcomp_print(ndo_t *ndo, u_int *indexp, void *infonode, const u_char *bp, u_int length)
{
    TC("Called { %s(%p, %p, %u, %p, %p, %u)", __func__, ndo, infonode, *indexp, 
        indexp, bp, length);

    const struct ipcomp *ipcomp;
    uint16_t cpi;
    uint8_t ipcomp_nh;
    uint8_t ipcomp_flags;

    u_int idx = *indexp;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    ndo->ndo_protocol = "ipcomp";
    ipcomp = (const struct ipcomp *)bp;
    cpi = GET_BE_U_2(ipcomp->comp_cpi);

    su = nd_get_fill_put_l1l2_node_level1(ifn, 0, 0, 0, "%s", LAYER_4_IPCOMP_CONTENT);

    ipcomp_nh = GET_U_1(ipcomp->comp_nxt);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, LAYER_4_IPCOMP_NXT, 
            ipcomp_nh, tok2str(ipproto_values, "unknown", ipcomp_nh));
    idx = idx + 1;

    ipcomp_flags = GET_U_1(ipcomp->comp_flags);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, LAYER_4_IPCOMP_FLAGS, 
            ipcomp_flags);
    idx = idx + 1;

    cpi = GET_BE_U_2(ipcomp->comp_cpi);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, LAYER_4_IPCOMP_CPI, 
            cpi);
    idx = idx + 2;

    *indexp = idx;

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%ld", (length - sizeof(struct ipcomp)));
    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
    snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "Next header %s, IPComp(cpi=0x%04x)", 
        tok2str(ipproto_values, "unknown", ipcomp_nh), cpi);

    RVoid();
}