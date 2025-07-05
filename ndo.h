

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
#include "funcattrs.h"
#include "pcap.h"

/*
 * Data types corresponding to multi-byte integral values within data
 * structures.  These are defined as arrays of octets, so that they're
 * not aligned on their "natural" boundaries, and so that you *must*
 * use the EXTRACT_ macros to extract them (which you should be doing
 * *anyway*, so as not to assume a particular byte order or alignment
 * in your code).
 *
 * We even want EXTRACT_U_1 used for 8-bit integral values, so we
 * define nd_uint8_t and nd_int8_t as arrays as well.
 */
typedef unsigned char nd_uint8_t[1];
typedef unsigned char nd_uint16_t[2];
typedef unsigned char nd_uint24_t[3];
typedef unsigned char nd_uint32_t[4];


#define MAC_ADDR_LEN                        (6U) /* length of MAC addresses */
typedef unsigned char nd_mac_addr[MAC_ADDR_LEN];

typedef unsigned char nd_uint16_t[2];

struct tok
{
  u_int v;       /* value */
  const char *s; /* string */
};

/* tok2str is deprecated */
extern const char *tok2str(const struct tok *, const char *, u_int);

typedef struct ndo_s ndo_t;

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

/**
 * @brief
 *  Define ndo global variables
 *  Load in the function analysis_network_frames
 *  In header.h declaration
 */
extern ndo_t *ndo;

extern void analysis_ts_print(ndo_t *, const struct timeval *, char *);

/*
 * Report a packet truncation with a longjmp().
 */
NORETURN void nd_trunc_longjmp(ndo_t *ndo);

/*
 * Test in two parts to avoid these warnings:
 * comparison of unsigned expression >= 0 is always true [-Wtype-limits],
 * comparison is always true due to limited range of data type [-Wtype-limits].
 */
#define IS_NOT_NEGATIVE(x) (((x) > 0) || ((x) == 0))

#define ND_TTEST_LEN(p, l) \
  (IS_NOT_NEGATIVE(l) && \
	((uintptr_t)ndo->ndo_snapend - (l) <= (uintptr_t)ndo->ndo_snapend && \
         (uintptr_t)(p) <= (uintptr_t)ndo->ndo_snapend - (l)))


/* Bail out if "l" bytes from "p" were not captured */
#ifdef ND_LONGJMP_FROM_TCHECK
#define ND_TCHECK_LEN(p, l) if (!ND_TTEST_LEN(p, l)) nd_trunc_longjmp(ndo)
#else
#define ND_TCHECK_LEN(p, l) if (!ND_TTEST_LEN(p, l)) goto trunc
#endif

/* Bail out if "*(p)" was not captured */
#define ND_TCHECK_SIZE(p) ND_TCHECK_LEN(p, sizeof(*(p)))


extern char *bittok2str_nosep(const struct tok *, const char *, u_int);

extern int macsec_print(ndo_t *ndo, const u_char **bp, void *infonode, void *su,
                u_int *index, u_int *lengthp, u_int *caplenp, u_int *hdrlenp);

extern int ethertype_print(ndo_t *ndo, u_int index, void *infonode,
                u_short ether_type, const u_char *p, u_int length, u_int caplen);

extern void arp_print(ndo_t *ndo, u_int index, void *infonode,
                      const u_char *bp, u_int length, u_int caplen);

#endif // __NDO_H__
