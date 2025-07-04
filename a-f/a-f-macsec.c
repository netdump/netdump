
#include "ndo.h"
#include "header.h"
#include "a-f-addrtoname.h"
#include "a-f-extract.h"

#define MACSEC_DEFAULT_ICV_LEN 16

/* Header format (SecTAG), following an Ethernet header
 * IEEE 802.1AE-2006 9.3
 *
 * +---------------------------------+----------------+----------------+
 * |        (MACsec ethertype)       |     TCI_AN     |       SL       |
 * +---------------------------------+----------------+----------------+
 * |                           Packet Number                           |
 * +-------------------------------------------------------------------+
 * |                     Secure Channel Identifier                     |
 * |                            (optional)                             |
 * +-------------------------------------------------------------------+
 *
 * MACsec ethertype = 0x88e5
 * TCI: Tag Control Information, set of flags
 * AN: association number, 2 bits
 * SL (short length): 6-bit length of the protected payload, if < 48
 * Packet Number: 32-bits packet identifier
 * Secure Channel Identifier: 64-bit unique identifier, usually
 *     composed of a MAC address + 16-bit port number
 */
struct macsec_sectag
{
    nd_uint8_t tci_an;
    nd_uint8_t short_length;
    nd_uint32_t packet_number;
    nd_uint8_t secure_channel_id[8]; /* optional */
};

/* IEEE 802.1AE-2006 9.5 */
#define MACSEC_TCI_VERSION 0x80
#define MACSEC_TCI_ES 0x40  /* end station */
#define MACSEC_TCI_SC 0x20  /* SCI present */
#define MACSEC_TCI_SCB 0x10 /* epon */
#define MACSEC_TCI_E 0x08   /* encryption */
#define MACSEC_TCI_C 0x04   /* changed text */
#define MACSEC_AN_MASK 0x03 /* association number */
#define MACSEC_TCI_FLAGS (MACSEC_TCI_ES | MACSEC_TCI_SC | MACSEC_TCI_SCB | MACSEC_TCI_E | MACSEC_TCI_C)
#define MACSEC_TCI_CONFID (MACSEC_TCI_E | MACSEC_TCI_C)
#define MACSEC_SL_MASK 0x3F /* short length */

#define MACSEC_SECTAG_LEN_NOSCI 6 /* length of MACsec header without SCI */
#define MACSEC_SECTAG_LEN_SCI 14  /* length of MACsec header with SCI */

#define SCI_FMT ", sci %016" PRIx64

static const struct tok macsec_flag_values[] = {
    {MACSEC_TCI_ES, "S"},
    {MACSEC_TCI_SC, "I"},
    {MACSEC_TCI_SCB, "B"},
    {MACSEC_TCI_E, "E"},
    {MACSEC_TCI_C, "C"},
    {0, NULL}
};

#define LAYER_2_MACSEC_TCI_FORMAT               "macsec tci(Tag Control Information): %02x; %s"
#define LAYER_2_MACSEC_AN_FORMAT                "macsec an(association number): %02x"
#define LAYER_2_MACSEC_SL_FORMAT                "macsec sl(short length): %02x"
#define LAYER_2_MACSEC_PN_FORMAT                "macsec pn(Packet Number): %u"
#define LAYER_2_MACSEC_SCI_FORMAT               "macsec sci(Secure Channel Identifier): %02x:%02x:%02x:%02x:%02x:%02x, port: %u"
#define LAYER_2_MACSEC_ICV_FORMAT               "macsec icv: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"

/* returns < 0 iff the packet can be decoded completely */
int macsec_print(ndo_t *ndo, const u_char **bp, void *infonode, void * su,
    u_int * index, u_int *lengthp, u_int *caplenp, u_int *hdrlenp)
{
    const char *save_protocol;
    const u_char *p = *bp;
    u_int length = *lengthp;
    u_int caplen = *caplenp;
    u_int hdrlen = *hdrlenp;
    const struct macsec_sectag *sectag = (const struct macsec_sectag *)p;
    u_int sectag_len;
    u_int short_length;

    infonode_t *ifn = (infonode_t *)infonode;

    save_protocol = ndo->ndo_protocol;
    ndo->ndo_protocol = "macsec";

    /* we need the full MACsec header in the capture */
    if (caplen < MACSEC_SECTAG_LEN_NOSCI)
    {
        TW(" [|%s]", ndo->ndo_protocol);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining caplen %u < %u]((invalid))",
                 caplen, MACSEC_SECTAG_LEN_NOSCI);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        ndo->ndo_protocol = save_protocol;
        return hdrlen + caplen;
    }

    if (length < MACSEC_SECTAG_LEN_NOSCI)
    {
        TW(" [|%s]", ndo->ndo_protocol);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining length %u < %u]((invalid))",
                 caplen, MACSEC_SECTAG_LEN_NOSCI);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        ndo->ndo_protocol = save_protocol;
        return hdrlen + caplen;
    }

    if (GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_SC)
    {
        sectag_len = MACSEC_SECTAG_LEN_SCI;
        if (caplen < MACSEC_SECTAG_LEN_SCI)
        {
            TW(" [|%s]", ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining caplen %u < %u]((invalid))",
                     caplen, MACSEC_SECTAG_LEN_SCI);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
            ndo->ndo_protocol = save_protocol;
            return hdrlen + caplen;
        }
        if (length < MACSEC_SECTAG_LEN_SCI)
        {
            TW(" [|%s]", ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining length %u < %u]((invalid))",
                     caplen, MACSEC_SECTAG_LEN_SCI);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
            ndo->ndo_protocol = save_protocol;
            return hdrlen + caplen;
        }
    }
    else
        sectag_len = MACSEC_SECTAG_LEN_NOSCI;

    if ((GET_U_1(ndo, sectag->short_length) & ~MACSEC_SL_MASK) != 0 ||
        GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_VERSION)
    {
        TW("((invalid))");
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "((invalid))");
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        ndo->ndo_protocol = save_protocol;
        return hdrlen + caplen;
    }

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index, LAYER_2_MACSEC_TCI_FORMAT, 
        (GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_FLAGS),
        bittok2str_nosep(macsec_flag_values, "none", GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_FLAGS)
    );

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index,
        LAYER_2_MACSEC_AN_FORMAT, GET_U_1(ndo, sectag->tci_an) & MACSEC_AN_MASK);

    *index = *index + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index,
        LAYER_2_MACSEC_SL_FORMAT, GET_U_1(ndo, sectag->short_length) & MACSEC_SL_MASK);

    *index = *index + 1;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index + sizeof(nd_uint32_t) - 1,
        LAYER_2_MACSEC_PN_FORMAT, GET_BE_U_4(ndo, sectag->packet_number));

    *index = *index + sizeof(nd_uint32_t);

    if (GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_SC) 
    {
        nd_get_fill_put_l1l2_node_level2(ifn, su, 0, *index, *index + sizeof(sectag->secure_channel_id) - 1,
                LAYER_2_MACSEC_SCI_FORMAT, 
                *(sectag->secure_channel_id[0]), *(sectag->secure_channel_id[1]),
                *(sectag->secure_channel_id[2]), *(sectag->secure_channel_id[3]),
                *(sectag->secure_channel_id[4]), *(sectag->secure_channel_id[5]),
                ntohs(((uint16_t)(*(sectag->secure_channel_id[6]) << 8)) | (uint16_t)(*(sectag->secure_channel_id[7])))
        );

        *index = *index + sizeof(sectag->secure_channel_id);
    }

    /* Skip the MACsec header. */
    *bp += sectag_len;
    *hdrlenp += sectag_len;

    /* Remove it from the lengths, as it's been processed. */
    *lengthp -= sectag_len;
    *caplenp -= sectag_len;

    if ((GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_CONFID))
    {
        /*
         * The payload is encrypted.  Print link-layer
         * information, if it hasn't already been printed.
         */
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "an %u, pn %u, flags %s, sl %u",
            GET_U_1(ndo, sectag->tci_an) & MACSEC_AN_MASK, GET_BE_U_4(ndo, sectag->packet_number),
            bittok2str_nosep(macsec_flag_values, "none", GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_FLAGS),
            GET_U_1(ndo, sectag->short_length) & MACSEC_SL_MASK
        );

        if (GET_U_1(ndo, sectag->tci_an) & MACSEC_TCI_SC) 
        {
            snprintf(ifn->brief + strlen(ifn->brief), INFONODE_BRIEF_LENGTH - strlen(ifn->brief), 
                SCI_FMT, GET_BE_U_8(ndo, sectag->secure_channel_id)
            );
        }

        /*
         * Tell our caller it can't be dissected.
         */
        ndo->ndo_protocol = save_protocol;
        return 0;
    }

    /*
     * The payload isn't encrypted; remove the
     * ICV length from the lengths, so our caller
     * doesn't treat it as payload.
     */
    if (*lengthp < MACSEC_DEFAULT_ICV_LEN)
    {
        TW(" [|%s]", ndo->ndo_protocol);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining length %u < %u]((invalid))",
                 *lengthp, MACSEC_DEFAULT_ICV_LEN);
        ndo->ndo_protocol = save_protocol;
        return hdrlen + caplen;
    }
    if (*caplenp < MACSEC_DEFAULT_ICV_LEN)
    {
        TW(" [|%s]", ndo->ndo_protocol);
        snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining caplen %u < %u]((invalid))",
                 *caplenp, MACSEC_DEFAULT_ICV_LEN);
        ndo->ndo_protocol = save_protocol;
        return hdrlen + caplen;
    }

    *lengthp -= MACSEC_DEFAULT_ICV_LEN;
    *caplenp -= MACSEC_DEFAULT_ICV_LEN;

    /*
     * Update the snapend thus the ICV field is not in the payload for
     * the caller.
     * The ICV (Integrity Check Value) is at the end of the frame, after
     * the secure data.
     */
    ndo->ndo_snapend -= MACSEC_DEFAULT_ICV_LEN;

    /*
     * If the SL field is non-zero, then it's the length of the
     * Secure Data; otherwise, the Secure Data is what's left
     * ver after the MACsec header and ICV are removed.
     */
    short_length = GET_U_1(ndo, sectag->short_length) & MACSEC_SL_MASK;
    if (short_length != 0)
    {
        /*
         * If the short length is more than we *have*,
         * that's an error.
         */
        if (short_length > *lengthp)
        {
            TW(" [|%s]", ndo->ndo_protocol);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining length %u < sl %u]((invalid))",
                     *lengthp, short_length);
            ndo->ndo_protocol = save_protocol;
            return hdrlen + caplen;
        }
        if (short_length > *caplenp)
        {
            TW(" [|%s]", ndo->ndo_protocol);
            snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "[remaining caplen %u < sl %u]((invalid))",
                     *caplenp, short_length);
            ndo->ndo_protocol = save_protocol;
            return hdrlen + caplen;
        }
        if (*lengthp > short_length)
            *lengthp = short_length;
        if (*caplenp > short_length)
            *caplenp = short_length;
    }

    ndo->ndo_protocol = save_protocol;

    const u_char *icv = p + sectag_len + *lengthp;

    nd_get_fill_put_l1l2_node_level2(ifn, su, 0, 
        *index + *lengthp, *index + *lengthp + MACSEC_DEFAULT_ICV_LEN - 1,
        LAYER_2_MACSEC_ICV_FORMAT, 
        icv[0], icv[1], icv[2], icv[3], icv[4], icv[5], icv[6], icv[7],
        icv[8], icv[9], icv[10], icv[11], icv[12], icv[13], icv[14], icv[15]
    );

    return -1;
}