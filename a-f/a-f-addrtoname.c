
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

#ifndef IN6ADDRSZ
#define IN6ADDRSZ 16 /* IPv6 T_AAAA */
#endif

#ifndef INT16SZ
#define INT16SZ 2 /* word size */
#endif

const char *
addrtostr(const void *src, char *dst, size_t size)
{
    const u_char *srcaddr = (const u_char *)src;
    const char digits[] = "0123456789";
    int i;
    const char *orig_dst = dst;

    if (size < INET_ADDRSTRLEN)
    {
        errno = ENOSPC;
        return NULL;
    }
    for (i = 0; i < 4; ++i)
    {
        int n = *srcaddr++;
        int non_zerop = 0;

        if (non_zerop || n / 100 > 0)
        {
            *dst++ = digits[n / 100];
            n %= 100;
            non_zerop = 1;
        }
        if (non_zerop || n / 10 > 0)
        {
            *dst++ = digits[n / 10];
            n %= 10;
            non_zerop = 1;
        }
        *dst++ = digits[n];
        if (i != 3)
            *dst++ = '.';
    }
    *dst++ = '\0';
    return orig_dst;
}

/*
 * Convert IPv6 binary address into presentation (printable) format.
 */
const char *
addrtostr6(const void *src, char *dst, size_t size)
{
    /*
     * Note that int32_t and int16_t need only be "at least" large enough
     * to contain a value of the specified size.  On some systems, like
     * Crays, there is no such thing as an integer variable with 16 bits.
     * Keep this in mind if you think this function should have been coded
     * to use pointer overlays.  All the world's not a VAX.
     */
    const u_char *srcaddr = (const u_char *)src;
    char *dp;
    size_t space_left, added_space;
    int snprintfed;
    struct
    {
        int base;
        int len;
    } best, cur;
    uint16_t words[IN6ADDRSZ / INT16SZ];
    int i;

    /* Preprocess:
     *  Copy the input (bytewise) array into a wordwise array.
     *  Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
        words[i] = (srcaddr[2 * i] << 8) | srcaddr[2 * i + 1];

    best.len = 0;
    best.base = -1;
    cur.len = 0;
    cur.base = -1;
    for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
    {
        if (words[i] == 0)
        {
            if (cur.base == -1)
                cur.base = i, cur.len = 1;
            else
                cur.len++;
        }
        else if (cur.base != -1)
        {
            if (best.base == -1 || cur.len > best.len)
                best = cur;
            cur.base = -1;
        }
    }
    if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
        best = cur;
    if (best.base != -1 && best.len < 2)
        best.base = -1;

    /* Format the result.
     */
    dp = dst;
    space_left = size;
    #define APPEND_CHAR(c)          \
    {                               \
        if (space_left == 0)        \
        {                           \
            errno = ENOSPC;         \
            return (NULL);          \
        }                           \
        *dp++ = c;                  \
        space_left--;               \
    }
    for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
    {
        /* Are we inside the best run of 0x00's?
         */
        if (best.base != -1 && i >= best.base && i < (best.base + best.len))
        {
            if (i == best.base)
                APPEND_CHAR(':');
            continue;
        }

        /* Are we following an initial run of 0x00s or any real hex?
         */
        if (i != 0)
            APPEND_CHAR(':');

        /* Is this address an encapsulated IPv4?
         */
        if (i == 6 && best.base == 0 &&
            (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
        {
            if (!addrtostr(srcaddr + 12, dp, space_left))
            {
                errno = ENOSPC;
                return (NULL);
            }
            added_space = strlen(dp);
            dp += added_space;
            space_left -= added_space;
            break;
        }
        snprintfed = snprintf(dp, space_left, "%x", words[i]);
        if (snprintfed < 0)
            return (NULL);
        if ((size_t)snprintfed >= space_left)
        {
            errno = ENOSPC;
            return (NULL);
        }
        dp += snprintfed;
        space_left -= snprintfed;
    }

    /* Was it a trailing run of 0x00's?
     */
    if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
        APPEND_CHAR(':');
    APPEND_CHAR('\0');

    return (dst);
}

/*
 * Return a name for the IP6 address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
const char *
ip6addr_string(ndo_t *ndo, const u_char *ap)
{
    static char ntop_buf[INET6_ADDRSTRLEN];

    memset(ntop_buf, 0, INET6_ADDRSTRLEN);

    return addrtostr6(ap, ntop_buf, sizeof(ntop_buf));
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
