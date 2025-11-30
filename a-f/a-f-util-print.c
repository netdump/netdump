
#include <sys/stat.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "header.h"

#define TOKBUFSIZE 128

/*
 * Print out a character, filtering out the non-printable ones
 */
void fn_print_char(ndo_t *ndo, u_char c, char * buffer)
{
    if (!ND_ISASCII(c))
    {
        c = ND_TOASCII(c);
        //ND_PRINT("M-");
        sprintf(buffer + strlen(buffer), "%s", "M-");
    }
    if (!ND_ASCII_ISPRINT(c))
    {
        c ^= 0x40; /* DEL to ?, others to alpha */
        //ND_PRINT("^");
        sprintf(buffer + strlen(buffer), "%s", "^");
    }
    //ND_PRINT("%c", c);
    sprintf(buffer + strlen(buffer), "%c", c);
}

/*
 * Convert a token value to a string; use "fmt" if not found.
 */
static const char *
tok2strbuf(const struct tok *lp, const char *fmt,
           u_int v, char *buf, size_t bufsize)
{
    if (lp != NULL)
    {
        while (lp->s != NULL)
        {
            if (lp->v == v)
                return (lp->s);
            ++lp;
        }
    }
    if (fmt == NULL)
        fmt = "#%d";

    (void)snprintf(buf, bufsize, fmt, v);
    return (const char *)buf;
}

/*
 * Convert a token value to a string; use "fmt" if not found.
 * Uses tok2strbuf() on one of four local static buffers of size TOKBUFSIZE
 * in round-robin fashion.
 */
const char *
tok2str(const struct tok *lp, const char *fmt,
        u_int v)
{
    static char buf[4][TOKBUFSIZE];
    static int idx = 0;
    char *ret;

    ret = buf[idx];
    idx = (idx + 1) & 3;
    return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are separated
 * if the s field is positive.
 *
 * A token matches iff it has one or more bits set and every bit that is set
 * in the token is set in v. Consequently, a 0 token never matches.
 */
static char *
bittok2str_internal(const struct tok *lp, const char *fmt,
                    u_int v, const char *sep)
{
    static char buf[1024 + 1]; /* our string buffer */
    char *bufp = buf;
    size_t space_left = sizeof(buf), string_size;
    const char *sepstr = "";

    while (lp != NULL && lp->s != NULL)
    {
        if (lp->v && (v & lp->v) == lp->v)
        {
            /* ok we have found something */
            if (space_left <= 1)
                return (buf); /* only enough room left for NUL, if that */
            string_size = strlcpy(bufp, sepstr, space_left);
            if (string_size >= space_left)
                return (buf); /* we ran out of room */
            bufp += string_size;
            space_left -= string_size;
            if (space_left <= 1)
                return (buf); /* only enough room left for NUL, if that */
            string_size = strlcpy(bufp, lp->s, space_left);
            if (string_size >= space_left)
                return (buf); /* we ran out of room */
            bufp += string_size;
            space_left -= string_size;
            sepstr = sep;
        }
        lp++;
    }

    if (bufp == buf)
        /* bummer - lets print the "unknown" message as advised in the fmt string if we got one */
        (void)snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
    return (buf);
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are not separated.
 */
char *
bittok2str_nosep(const struct tok *lp, const char *fmt,
                 u_int v)
{
    return (bittok2str_internal(lp, fmt, v, ""));
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are comma separated.
 */
char *
bittok2str(const struct tok *lp, const char *fmt,
           u_int v)
{
    return (bittok2str_internal(lp, fmt, v, ", "));
}