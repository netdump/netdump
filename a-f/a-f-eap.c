
#include "header.h"
#include "a-f-extract.h"

#define LAYER_3_EAPOL_FORMAT                "%s"
#define LAYER_3_EAPOL_CONTENT               "802.1X Authentication"
#define LAYER_3_EAPOL_H_VERSION             "EAPOL Header Version: %u"
#define LAYER_3_EAPOL_H_TYPE                "EAPOL Header Type: %s (%u)"
#define LAYER_3_EAPOL_H_LENGTH              "EAPOL Header Length: %u"
#define LAYER_3_EAP_H_CODE                  "EAP Header Code: %s (%u)"
#define LAYER_3_EAP_H_ID                    "EAP Header ID: %u"
#define LAYER_3_EAP_H_LENGTH                "EAP Header Length: %u"
#define LAYER_3_EAP_DATA_TYPE               "EAP Data Type: %s (%u)"
#define LAYER_3_EAP_DATA                    "EAP DATA"

#define EAP_FRAME_TYPE_PACKET               0
#define EAP_FRAME_TYPE_START                1
#define EAP_FRAME_TYPE_LOGOFF               2
#define EAP_FRAME_TYPE_KEY                  3
#define EAP_FRAME_TYPE_ENCAP_ASF_ALERT      4

struct eap_frame_t
{
    nd_uint8_t version;
    nd_uint8_t type;
    nd_uint16_t length;
};

static const struct tok eap_frame_type_values[] = {
    {EAP_FRAME_TYPE_PACKET, "EAP packet"},
    {EAP_FRAME_TYPE_START, "EAPOL start"},
    {EAP_FRAME_TYPE_LOGOFF, "EAPOL logoff"},
    {EAP_FRAME_TYPE_KEY, "EAPOL key"},
    {EAP_FRAME_TYPE_ENCAP_ASF_ALERT, "Encapsulated ASF alert"},
    {0, NULL}
};

/* RFC 3748 */
struct eap_packet_t
{
    nd_uint8_t code;
    nd_uint8_t id;
    nd_uint16_t length;
};

#define EAP_REQUEST         1
#define EAP_RESPONSE        2
#define EAP_SUCCESS         3
#define EAP_FAILURE         4

static const struct tok eap_code_values[] = {
    {EAP_REQUEST, "Request"},
    {EAP_RESPONSE, "Response"},
    {EAP_SUCCESS, "Success"},
    {EAP_FAILURE, "Failure"},
    {0, NULL}
};

#define EAP_TYPE_NO_PROPOSED                0
#define EAP_TYPE_IDENTITY                   1
#define EAP_TYPE_NOTIFICATION               2
#define EAP_TYPE_NAK                        3
#define EAP_TYPE_MD5_CHALLENGE              4
#define EAP_TYPE_OTP                        5
#define EAP_TYPE_GTC                        6
#define EAP_TYPE_TLS                        13  /* RFC 5216 */
#define EAP_TYPE_SIM                        18  /* RFC 4186 */
#define EAP_TYPE_TTLS                       21 /* RFC 5281, draft-funk-eap-ttls-v0-01.txt */
#define EAP_TYPE_AKA                        23  /* RFC 4187 */
#define EAP_TYPE_FAST                       43 /* RFC 4851 */
#define EAP_TYPE_EXPANDED_TYPES             254
#define EAP_TYPE_EXPERIMENTAL               255

static const struct tok eap_type_values[] = {
    {EAP_TYPE_NO_PROPOSED, "No proposed"},
    {EAP_TYPE_IDENTITY, "Identity"},
    {EAP_TYPE_NOTIFICATION, "Notification"},
    {EAP_TYPE_NAK, "Nak"},
    {EAP_TYPE_MD5_CHALLENGE, "MD5-challenge"},
    {EAP_TYPE_OTP, "OTP"},
    {EAP_TYPE_GTC, "GTC"},
    {EAP_TYPE_TLS, "TLS"},
    {EAP_TYPE_SIM, "SIM"},
    {EAP_TYPE_TTLS, "TTLS"},
    {EAP_TYPE_AKA, "AKA"},
    {EAP_TYPE_FAST, "FAST"},
    {EAP_TYPE_EXPANDED_TYPES, "Expanded types"},
    {EAP_TYPE_EXPERIMENTAL, "Experimental"},
    {0, NULL}
};

#define EAP_TLS_EXTRACT_BIT_L(x)            (((x) & 0x80) >> 7)

/* RFC 5216 - EAP TLS bits */
#define EAP_TLS_FLAGS_LEN_INCLUDED          (1 << 7)
#define EAP_TLS_FLAGS_MORE_FRAGMENTS        (1 << 6)
#define EAP_TLS_FLAGS_START                 (1 << 5)

#if 0
static const struct tok eap_tls_flags_values[] = {
    {EAP_TLS_FLAGS_LEN_INCLUDED, "L bit"},
    {EAP_TLS_FLAGS_MORE_FRAGMENTS, "More fragments bit"},
    {EAP_TLS_FLAGS_START, "Start bit"},
    {0, NULL}
};
#endif

#define EAP_TTLS_VERSION(x)                 ((x) & 0x07)

/* EAP-AKA and EAP-SIM - RFC 4187 */
#define EAP_AKA_CHALLENGE                   1
#define EAP_AKA_AUTH_REJECT                 2
#define EAP_AKA_SYNC_FAILURE                4
#define EAP_AKA_IDENTITY                    5
#define EAP_SIM_START                       10
#define EAP_SIM_CHALLENGE                   11
#define EAP_AKA_NOTIFICATION                12
#define EAP_AKA_REAUTH                      13
#define EAP_AKA_CLIENT_ERROR                14

#if 0
static const struct tok eap_aka_subtype_values[] = {
    {EAP_AKA_CHALLENGE, "Challenge"},
    {EAP_AKA_AUTH_REJECT, "Auth reject"},
    {EAP_AKA_SYNC_FAILURE, "Sync failure"},
    {EAP_AKA_IDENTITY, "Identity"},
    {EAP_SIM_START, "Start"},
    {EAP_SIM_CHALLENGE, "Challenge"},
    {EAP_AKA_NOTIFICATION, "Notification"},
    {EAP_AKA_REAUTH, "Reauth"},
    {EAP_AKA_CLIENT_ERROR, "Client error"},
    {0, NULL}
};
#endif

int eap_print(ndo_t *ndo, void *infonode, l1l2_node_t *su, const u_char *cp, u_int length)
{
    TC("Called { %s(%p, %p, %p, %p, %u)", __func__, ndo, infonode, su, cp, length);

    u_int type, subtype, len;
    //u_int count;
    //const char *sep;

    ndo->ndo_protocol = "eap";
    type = GET_U_1(cp);
    len = GET_BE_U_2(cp + 2);

    infonode_t *ifn = (infonode_t *)infonode;

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_EAP_H_CODE,
            tok2str(eap_code_values, "unknown", type), type);

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_EAP_H_ID, GET_U_1((cp + 1)));

    nd_filling_l2(ifn, su, 0, 2, LAYER_3_EAP_H_LENGTH, len);

    if (!ND_TTEST_LEN(cp, len))
    {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "truncation (invalid)");
        goto trunc;
    }

    if (type == EAP_REQUEST || type == EAP_RESPONSE)
    {
        if (len < 5) {
            snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "too short for EAP request/response (invalid)");
            goto trunc;
        }
        subtype = GET_U_1(cp + 4);
        nd_filling_l2(ifn, su, 0, 1, LAYER_3_EAP_DATA_TYPE,
                tok2str(eap_type_values, "unknown", subtype), subtype);

        nd_filling_l2(ifn, su, 0, len, LAYER_3_EAP_DATA);
    }

    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", len);
    RInt(0);

trunc:
    RInt(1);
}

void eapol_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length)
{

    TC("Called { %s(%p, %p, %p, %u)", __func__, ndo, infonode, bp, length);

    const struct eap_frame_t *eap;
    u_int eap_type, eap_len;

    ndo->ndo_protocol = "eap";
    eap = (const struct eap_frame_t *)bp;
    infonode_t *ifn = (infonode_t *)infonode;

    snprintf(ifn->protocol, INFONODE_PROTOCOL_LENGTH, "%s", ndo->ndo_protocol);

    if (!ND_TTEST_LEN(eap, sizeof(*(eap)))) {
        snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "truncation (invalid)");
        goto trunc;
    }

    l1l2_node_t *su = NULL;
    su = nd_filling_l1(ifn, 0, LAYER_3_EAPOL_FORMAT, LAYER_3_EAPOL_CONTENT);

    nd_filling_l2(ifn, su, 0, 1, LAYER_3_EAPOL_H_VERSION, GET_U_1(eap->version));

    eap_type = GET_U_1(eap->type);
    nd_filling_l2(ifn, su, 0, 1, LAYER_3_EAPOL_H_TYPE,
            tok2str(eap_frame_type_values, "unknown", eap_type),
            eap_type);

    nd_filling_l2(ifn, su, 0, 2, LAYER_3_EAPOL_H_LENGTH, GET_BE_U_2(eap->length));

    bp += sizeof(struct eap_frame_t);
    eap_len = GET_BE_U_2(eap->length);

    switch (eap_type)
    {
        case EAP_FRAME_TYPE_PACKET:
            if (eap_len == 0)
            {
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "truncation (invalid)");
                goto trunc;
            }
            if (eap_len != GET_BE_U_2(bp + 2))
            {
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "EAP fragment? (invalid)");
                goto trunc;
            }
            if ((GET_BE_U_2(bp + 2)) < 4)
            {
                snprintf(ifn->brief, INFONODE_BRIEF_LENGTH, "too short for EAP header (invalid)");
                goto trunc;
            }
            if (eap_print(ndo, infonode, su, bp, eap_len))
            {
                goto trunc;
            }
            RVoid();
        case EAP_FRAME_TYPE_LOGOFF:
        case EAP_FRAME_TYPE_ENCAP_ASF_ALERT:
            default:
                break;
    }

    RVoid();

trunc:
    snprintf(ifn->length, INFONODE_LENGTH_LENGTH, "%u", length);
    
    RVoid();
}