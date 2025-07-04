
#include "header.h"
#include "a-f-addrtoname.h"
#include "a-f-extract.h"
#include "a-f-oui.h"

static const char hex[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/*
 * Convert an octet to two hex digits.
 *
 * Coverity appears either:
 *
 *    not to believe the C standard when it asserts that a uint8_t is
 *    exactly 8 bits in size;
 *
 *    not to believe that an unsigned type of exactly 8 bits has a value
 *    in the range of 0 to 255;
 *
 *    not to believe that, for a range of unsigned values, if you shift
 *    one of those values right by 4 bits, the maximum result value is
 *    the maximum value shifted right by 4 bits, with no stray 1's shifted
 *    in;
 *
 *    not to believe that 255 >> 4 is 15;
 *
 * so it gets upset that we're taking a "tainted" unsigned value, shifting
 * it right 4 bits, and using it as an index into a 16-element array.
 *
 * So we do a stupid pointless masking of the result of the shift with
 * 0xf, to hammer the point home to Coverity.
 */
static inline char *
octet_to_hex(char *cp, uint8_t octet)
{
    *cp++ = hex[(octet >> 4) & 0xf];
    *cp++ = hex[(octet >> 0) & 0xf];
    return (cp);
}

void etheraddr_string(ndo_t *ndo, const uint8_t *ep, char * roomage)
{
    int i;
    char *cp;
    int oui;
    char buf[BUFSIZE];

    cp = buf;
    oui = EXTRACT_BE_U_3(ep);
    cp = octet_to_hex(cp, *ep++);
    for (i = 5; --i >= 0;)
    {
        *cp++ = ':';
        cp = octet_to_hex(cp, *ep++);
    }

    snprintf(cp, BUFSIZE - (2 + 5 * 3), " (oui %s)",
                 tok2str(oui_values, "Unknown", oui));

    snprintf(roomage, BUFSIZE, "%s", buf);

    return ;
}
