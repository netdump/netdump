
#include "header.h"
#include "a-f-addrtoname.h"
#include "a-f-extract.h"
#include "a-f-oui.h"

/*
 * A faster replacement for inet_ntoa().
 */
const char *
intoa(uint32_t addr)
{
    char *cp;
    u_int byte;
    int n;
    static char buf[sizeof(".xxx.xxx.xxx.xxx")];

    memset(buf, 0, sizeof(".xxx.xxx.xxx.xxx"));

    addr = ntohl(addr);
    cp = buf + sizeof(buf);
    *--cp = '\0';

    n = 4;
    do
    {
        byte = addr & 0xff;
        *--cp = (char)(byte % 10) + '0';
        byte /= 10;
        if (byte > 0)
        {
            *--cp = (char)(byte % 10) + '0';
            byte /= 10;
            if (byte > 0)
                *--cp = (char)byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    return cp + 1;
}

/*
 * Return a name for the IP address pointed to by ap.  This address
 * is assumed to be in network byte order.
 *
 * NOTE: ap is *NOT* necessarily part of the packet data, so you
 * *CANNOT* use the ND_TCHECK_* or ND_TTEST_* macros on it.  Furthermore,
 * even in cases where it *is* part of the packet data, the caller
 * would still have to check for a null return value, even if it's
 * just printing the return value with "%s" - not all versions of
 * printf print "(null)" with "%s" and a null pointer, some of them
 * don't check for a null pointer and crash in that case.
 *
 * The callers of this routine should, before handing this routine
 * a pointer to packet data, be sure that the data is present in
 * the packet buffer.  They should probably do those checks anyway,
 * as other data at that layer might not be IP addresses, and it
 * also needs to check whether they're present in the packet buffer.
 */
const char *
ipaddr_string(ndo_t *ndo, const u_char *ap)
{

    uint32_t addr;
    memcpy(&addr, ap, sizeof(addr));

    return intoa(addr);
}



static const char hex[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

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

const char * etheraddr_string(ndo_t *ndo, const uint8_t *ep)
{
    int i;
    char *cp;
    int oui;
    static char buf[BUFSIZE];

    memset(buf, 0, BUFSIZE);

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

    return buf;
}
