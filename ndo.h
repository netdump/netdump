

#ifndef __NDO_H__
#define __NDO_H__

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdint.h>
#include <stddef.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <setjmp.h>

#define IF_PRINTER_ARGS (ndo_t *, void *, const struct pcap_pkthdr *, const unsigned char *)

typedef void(*if_printer) IF_PRINTER_ARGS;

/*
 * In case the data in a buffer needs to be processed by being decrypted,
 * decompressed, etc. before it's dissected, we can't process it in place,
 * we have to allocate a new buffer for the processed data.
 *
 * We keep a stack of those buffers; when we allocate a new buffer, we
 * push the current one onto a stack, and when we're done with the new
 * buffer, we free the current buffer and pop the previous one off the
 * stack.
 *
 * A buffer has a beginning and end pointer, and a link to the previous
 * buffer on the stack.
 *
 * In other cases, we temporarily adjust the snapshot end to reflect a
 * packet-length field in the packet data and, when finished dissecting
 * that part of the packet, restore the old snapshot end.  We keep that
 * on the stack with null buffer pointer, meaning there's nothing to
 * free.
 */
struct netdissect_saved_packet_info
{
    unsigned char *ndspi_buffer;                     /* pointer to allocated buffer data */
    const unsigned char *ndspi_packetp;              /* saved beginning of data */
    const unsigned char *ndspi_snapend;              /* saved end of data */
    struct netdissect_saved_packet_info *ndspi_prev; /* previous buffer on the stack */
};

/* 'val' value(s) for longjmp */
#define ND_TRUNCATED 1

typedef struct ndo_s
{
    int ndo_bflag;                  /* print 4 byte ASes in ASDOT notation */
    int ndo_eflag;                  /* print ethernet header */
    int ndo_fflag;                  /* don't translate "foreign" IP address */
    int ndo_Kflag;                  /* don't check IP, TCP or UDP checksums */
    int ndo_nflag;                  /* leave addresses as numbers */
    int ndo_Nflag;                  /* remove domains from printed host names */
    int ndo_qflag;                  /* quick (shorter) output */
    int ndo_Sflag;                  /* print raw TCP sequence numbers */
    int ndo_tflag;                  /* print packet arrival time */
    int ndo_uflag;                  /* Print undecoded NFS handles */
    int ndo_vflag;                  /* verbosity level */
    int ndo_xflag;                  /* print packet in hex */
    int ndo_Xflag;                  /* print packet in hex/ASCII */
    int ndo_Aflag;                  /* print packet only in ASCII observing TAB,
                                     * LF, CR and SPACE as graphical chars
                                     */
    int ndo_Hflag;                  /* dissect 802.11s draft mesh standard */
    const char *ndo_protocol;       /* protocol */
    jmp_buf ndo_early_end;          /* jmp_buf for setjmp()/longjmp() */
    void *ndo_last_mem_p;           /* pointer to the last allocated memory chunk */
    int ndo_packet_number;          /* print a packet number in the beginning of line */
    int ndo_suppress_default_print; /* don't use default_print() for unknown packet types */
    int ndo_tstamp_precision;       /* requested time stamp precision */
    const char *program_name;       /* Name of the program using the library */

    char *ndo_espsecret;
    struct sa_list *ndo_sa_list_head; /* used by print-esp.c */
    struct sa_list *ndo_sa_default;

    char *ndo_sigsecret; /* Signature verification secret key */

    int ndo_packettype; /* as specified by -T */

    int ndo_snaplen;
    int ndo_ll_hdr_len; /* link-layer header length */

    /*global pointers to beginning and end of current packet (during printing) */
    const unsigned char *ndo_packetp;
    const unsigned char *ndo_snapend;

    /* stack of saved packet boundary and buffer information */
    struct netdissect_saved_packet_info *ndo_packet_info_stack;

    /* pointer to the if_printer function */
    if_printer ndo_if_printer;

#if 0
	/* pointer to void function to output stuff */
	void (*ndo_default_print)(netdissect_options *,
				const unsigned char *bp, unsigned int length);

	/* pointer to function to do regular output */
	int  (*ndo_printf)(netdissect_options *,
				const char *fmt, ...)
				PRINTFLIKE_FUNCPTR(2, 3);
	/* pointer to function to output errors */
	void NORETURN_FUNCPTR (*ndo_error)(netdissect_options *,
						status_exit_codes_t status,
						const char *fmt, ...)
						PRINTFLIKE_FUNCPTR(3, 4);
	/* pointer to function to output warnings */
	void (*ndo_warning)(netdissect_options *,
				const char *fmt, ...)
				PRINTFLIKE_FUNCPTR(2, 3);
#endif
} ndo_t;

extern void analysis_ts_print(ndo_t *, const struct timeval *, char *);

#endif  // __NDO_H__
