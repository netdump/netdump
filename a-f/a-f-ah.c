/*	$NetBSD: print-ah.c,v 1.4 1996/05/20 00:41:16 fvdl Exp $	*/

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994
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

/* \summary: IPSEC Authentication Header printer */

#include "ndo.h"
#include "header.h"
#include "a-f-extract.h"
#include "a-f-ipproto.h"
#include "a-f-ah.h"

int ah_print(ndo_t *ndo, u_int * indexp, void *infonode, const u_char *bp)
{

    TC("Called { %s(%p, %p, %u, %p, %p)", __func__, ndo, infonode, *indexp, indexp, bp);

    const struct ah *ah;
    uint8_t ah_nh;
    uint8_t ah_len;
    int ah_hdr_len;
    uint16_t reserved;
    const u_char *p;

    u_int idx = *indexp;
    infonode_t *ifn = (infonode_t *)infonode;
    l1l2_node_t *su = NULL;

    ah = (const struct ah *)bp;

    /*
     * RFC4302
     *
     * 2.2.  Payload Length
     *
     *    This 8-bit field specifies the length of AH in 32-bit words (4-byte
     *    units), minus "2".
     */
    ah_len = GET_U_1(ah->ah_len);
    ah_hdr_len = (ah_len + 2) * 4;

    // need judgment ah_len and ah_hdr_len

    su = nd_get_fill_put_l1l2_node_level1(ifn, 0, 0, 0, "%s", LAYER_4_AH_CONTENT);

    ah_nh = GET_U_1(ah->ah_nxt);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, LAYER_4_AH_NEXT_HEADER, 
            ah_nh, tok2str(ipproto_values, "unknown", ah_nh));
    idx = idx + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx, LAYER_4_AH_PAYLOAD_LEN, 
            ah_len, ah_hdr_len);
    idx = idx + 1;

    reserved = GET_BE_U_2(ah->ah_reserved);
    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 2 - 1, LAYER_4_AH_RSVD, 
            reserved);
    idx = idx + 2;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, LAYER_4_AH_SPI, 
            GET_BE_U_4(ah->ah_spi));
    idx = idx + 4;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + 4 - 1, LAYER_4_AH_SEQ, 
            GET_BE_U_4(ah->ah_seq));
    idx = idx + 4;

    u_int temp = 0;
    u_char buffer[80] = {0};
    for (p = (const u_char *)(ah + 1); p < bp + ah_hdr_len; p++) {
        snprintf((char *)(buffer + strlen((const char *)buffer)), (80 - strlen((const char *)buffer)), "%02x", GET_U_1(p));
        temp++;
    }

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, idx, idx + temp - 1, LAYER_4_AH_ICV, 
            buffer);
    idx = idx + temp;

    *indexp = idx;

    RInt(ah_hdr_len);
}