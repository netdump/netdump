

#include "ndo.h"
#include "header.h"
#include "funcattrs.h"

/*
 * In a given ndo_t structure:
 *
 *    push the current packet information onto the packet information
 *    stack;
 *
 *    given a pointer into the packet and a length past that point in
 *    the packet, calculate a new snapshot end that's at the lower
 *    of the current snapshot end and that point in the packet;
 *
 *    set the snapshot end to that new value.
 */
int nd_push_snaplen(ndo_t *ndo, const u_char *bp, const u_int newlen)
{
    struct ndo_saved_packet_info *ndspi;
    u_int snaplen_remaining;

    ndspi = (struct ndo_saved_packet_info *)malloc(sizeof(struct ndo_saved_packet_info));
    if (ndspi == NULL)
        return (0);             /* fail */
    ndspi->ndspi_buffer = NULL; /* no new buffer */
    ndspi->ndspi_packetp = ndo->ndo_packetp;
    ndspi->ndspi_snapend = ndo->ndo_snapend;
    ndspi->ndspi_prev = ndo->ndo_packet_info_stack;

    /*
     * Push the saved previous data onto the stack.
     */
    ndo->ndo_packet_info_stack = ndspi;

    /*
     * Find out how many bytes remain after the current snapend.
     *
     * We're restricted to packets with at most UINT_MAX bytes;
     * cast the result to u_int, so that we don't get truncation
     * warnings on LP64 and LLP64 platforms.  (ptrdiff_t is
     * signed and we want an unsigned difference; the pointer
     * should at most be equal to snapend, and must *never*
     * be past snapend.)
     */
    snaplen_remaining = (u_int)(ndo->ndo_snapend - bp);

    /*
     * If the new snapend is smaller than the one calculated
     * above, set the snapend to that value, otherwise leave
     * it unchanged.
     */
    if (newlen <= snaplen_remaining)
    {
        /* Snapend isn't past the previous snapend */
        ndo->ndo_snapend = bp + newlen;
    }

    return (1); /* success */
}

void nd_pop_packet_info(ndo_t *ndo)
{
    struct ndo_saved_packet_info *ndspi;

    ndspi = ndo->ndo_packet_info_stack;
    ndo->ndo_packetp = ndspi->ndspi_packetp;
    ndo->ndo_snapend = ndspi->ndspi_snapend;
    ndo->ndo_packet_info_stack = ndspi->ndspi_prev;

    free(ndspi->ndspi_buffer);
    free(ndspi);
}

NORETURN void
nd_trunc_longjmp(ndo_t *ndo)
{
    longjmp(ndo->ndo_early_end, ND_TRUNCATED);
#ifdef _AIX
    /*
     * In AIX <setjmp.h> decorates longjmp() with "#pragma leaves", which tells
     * XL C that the function is noreturn, but GCC remains unaware of that and
     * yields a "'noreturn' function does return" warning.
     */
    ND_UNREACHABLE
#endif /* _AIX */
}
