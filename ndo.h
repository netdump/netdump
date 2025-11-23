

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
 * Check whether this is GCC major.minor or a later release, or some
 * compiler that claims to be "just like GCC" of that version or a
 * later release.
 */

#if !defined(__GNUC__)
/* Not GCC and not "just like GCC" */
#define ND_IS_AT_LEAST_GNUC_VERSION(major, minor) 0
#else
/* GCC or "just like GCC" */
#define ND_IS_AT_LEAST_GNUC_VERSION(major, minor) \
  (__GNUC__ > (major) ||                          \
   (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#endif

#if __has_attribute(unused) || ND_IS_AT_LEAST_GNUC_VERSION(2, 0)
/*
 * Compiler with support for __attribute__((unused)), or GCC 2.0 and
 * later, so it supports __attribute__((unused)).
 */
#define _U_ __attribute__((unused))
#else
/*
 * We don't know of any way to mark a variable as unused.
 */
#define _U_
#endif

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
typedef unsigned char nd_uint40_t[5];
typedef unsigned char nd_uint48_t[6];
typedef unsigned char nd_uint56_t[7];
typedef unsigned char nd_uint64_t[8];

typedef signed char nd_int8_t[1];

/*
 * "unsigned char" so that sign extension isn't done on the
 * individual bytes while they're being assembled.  Use
 * GET_S_BE_n() and GET_S_LE_n() macros to extract the value
 * as a signed integer.
 */
typedef unsigned char nd_int16_t[2];
typedef unsigned char nd_int24_t[3];
typedef unsigned char nd_int32_t[4];
typedef unsigned char nd_int40_t[5];
typedef unsigned char nd_int48_t[6];
typedef unsigned char nd_int56_t[7];
typedef unsigned char nd_int64_t[8];

/*
 * Use this for IPv4 addresses and netmasks.
 *
 * It's defined as an array of octets, so that it's not guaranteed to
 * be aligned on its "natural" boundary (in some packet formats, it
 * *isn't* so aligned).  We have separate EXTRACT_ calls for them;
 * sometimes you want the host-byte-order value, other times you want
 * the network-byte-order value.
 *
 * Don't use EXTRACT_BE_U_4() on them, use EXTRACT_IPV4_TO_HOST_ORDER()
 * if you want them in host byte order and EXTRACT_IPV4_TO_NETWORK_ORDER()
 * if you want them in network byte order (which you want with system APIs
 * that expect network-order IPv4 addresses, such as inet_ntop()).
 *
 * If, on your little-endian machine (e.g., an "IBM-compatible PC", no matter
 * what the OS, or an Intel Mac, no matter what the OS), you get the wrong
 * answer, and you've used EXTRACT_BE_U_4(), do *N*O*T* "fix" this by using
 * EXTRACT_LE_U_4(), fix it by using EXTRACT_IPV4_TO_NETWORK_ORDER(),
 * otherwise you're breaking the result on big-endian machines (e.g.,
 * most PowerPC/Power ISA machines, System/390 and z/Architecture, SPARC,
 * etc.).
 *
 * Yes, people do this; that's why Wireshark has tvb_get_ipv4(), to extract
 * an IPv4 address from a packet data buffer; it was introduced in reaction
 * to somebody who *had* done that.
 */
typedef unsigned char nd_ipv4[4];

/*
 * Use this for IPv6 addresses and netmasks.
 */
typedef unsigned char nd_ipv6[16];

/*
 * Use this for MAC addresses.
 */
#define MAC_ADDR_LEN 6U /* length of MAC addresses */
typedef unsigned char nd_mac_addr[MAC_ADDR_LEN];

/*
 * Use this for blobs of bytes; make them arrays of nd_byte.
 */
typedef unsigned char nd_byte;


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
struct ndo_saved_packet_info
{
    unsigned char *ndspi_buffer;                      /* pointer to allocated buffer data */
    const unsigned char *ndspi_packetp;               /* saved beginning of data */
    const unsigned char *ndspi_snapend;               /* saved end of data */
    struct ndo_saved_packet_info *ndspi_prev;         /* previous buffer on the stack */
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
    struct ndo_saved_packet_info *ndo_packet_info_stack;

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

#if (defined(__i386__) || defined(_M_IX86) || defined(__X86__) || defined(__x86_64__) || defined(_M_X64)) ||     \
    (defined(__arm__) || defined(_M_ARM) || defined(__aarch64__)) ||                                             \
    (defined(__m68k__) && (!defined(__mc68000__) && !defined(__mc68010__))) ||                                   \
    (defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)) || \
    (defined(__s390__) || defined(__s390x__) || defined(__zarch__)) ||                                           \
    defined(__vax__)
/*
 * The processor natively handles unaligned loads, so just use memcpy()
 * and memcmp(), to enable those optimizations.
 *
 * XXX - are those all the x86 tests we need?
 * XXX - do we need to worry about ARMv1 through ARMv5, which didn't
 * support unaligned loads, and, if so, do we need to worry about all
 * of them, or just some of them, e.g. ARMv5?
 * XXX - are those the only 68k tests we need not to generated
 * unaligned accesses if the target is the 68000 or 68010?
 * XXX - are there any tests we don't need, because some definitions are for
 * compilers that also predefine the GCC symbols?
 * XXX - do we need to test for both 32-bit and 64-bit versions of those
 * architectures in all cases?
 */
#define UNALIGNED_MEMCPY(p, q, l) memcpy((p), (q), (l))
#define UNALIGNED_MEMCMP(p, q, l) memcmp((p), (q), (l))
#else
/*
 * The processor doesn't natively handle unaligned loads,
 * and the compiler might "helpfully" optimize memcpy()
 * and memcmp(), when handed pointers that would normally
 * be properly aligned, into sequences that assume proper
 * alignment.
 *
 * Do copies and compares of possibly-unaligned data by
 * calling routines that wrap memcpy() and memcmp(), to
 * prevent that optimization.
 */
extern void unaligned_memcpy(void *, const void *, size_t);
extern int unaligned_memcmp(const void *, const void *, size_t);
#define UNALIGNED_MEMCPY(p, q, l) unaligned_memcpy((p), (q), (l))
#define UNALIGNED_MEMCMP(p, q, l) unaligned_memcmp((p), (q), (l))
#endif

extern WARN_UNUSED_RESULT int nd_push_buffer(ndo_t *, u_char *, const u_char *, const u_int);
extern WARN_UNUSED_RESULT int nd_push_snaplen(ndo_t *, const u_char *, const u_int);
extern void nd_change_snaplen(ndo_t *, const u_char *, const u_int);
extern void nd_pop_packet_info(ndo_t *);
extern void nd_pop_all_packet_info(ndo_t *);

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

#define ND_MIN(a, b) ((a) > (b) ? (b) : (a))
#define ND_MAX(a, b) ((b) > (a) ? (b) : (a))

/* For source or destination ports tests (UDP, TCP, ...) */
#define IS_SRC_OR_DST_PORT(p) (sport == (p) || dport == (p))

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

/*
 * Number of bytes between two pointers.
 */
#define ND_BYTES_BETWEEN(p1, p2) ((const u_char *)(p1) >= (const u_char *)(p2) ? 0 : ((u_int)(((const u_char *)(p2)) - (const u_char *)(p1))))

/*
 * Number of bytes remaining in the captured data, starting at the
 * byte pointed to by the argument.
 */
#define ND_BYTES_AVAILABLE_AFTER(p) ((const u_char *)(p) < ndo->ndo_packetp ? 0 : ND_BYTES_BETWEEN((p), ndo->ndo_snapend))

/* tok2str is deprecated */
extern const char *tok2str(const struct tok *, const char *, u_int);
extern char *bittok2str(const struct tok *, const char *, u_int);
extern char *bittok2str_nosep(const struct tok *, const char *, u_int);

/*
 * Structure passed to some printers to allow them to print
 * link-layer address information if ndo_eflag isn't set
 * (because they are for protocols that don't have their
 * own addresses, so that we'd want to report link-layer
 * address information).
 *
 * This contains a pointer to an address and a pointer to a routine
 * to which we pass that pointer in order to get a string.
 */
struct lladdr_info
{
  const char *(*addr_string)(ndo_t *, const u_char *);
  const u_char *addr;
};

/* The printer routines. */

extern int ah_print(ndo_t *ndo, void *infonode, const u_char *bp);

extern int macsec_print(ndo_t *ndo, const u_char **bp, void *infonode, void *su,
                    u_int *lengthp, u_int *caplenp, u_int *hdrlenp);

extern int ethertype_print(ndo_t *ndo, void *infonode, u_short ether_type, 
					const u_char *p, u_int length, u_int caplen,
                    const struct lladdr_info *src, const struct lladdr_info *dst);

extern void ip_print(ndo_t *ndo, void *infonode, const u_char *bp, const u_int length);

extern void ipcomp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length);

extern void udp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length, 
                    const u_char *bp2, int fragmented, u_int ttl_hl);

extern void tcp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length, 
                    const u_char *bp2, int fragmented);

extern void icmp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int plen, 
                    const u_char *bp2, int fragmented);

extern void icmp6_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length, 
                    const u_char *bp2, int fragmented);

extern void ip6_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length);

extern void arp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length, u_int caplen);

extern int hbhopt_process(ndo_t *ndo, void *infonode, void *_su, const u_char *bp, 
                    int *found_jumbo, uint32_t *jumbolen);

extern int dstopt_process(ndo_t *ndo, void *infonode, void *_su, const u_char *bp);

extern int frag6_print(ndo_t *ndo, void *infonode, void *_su, const u_char *bp, const char *bp2);

extern int rt6_print(ndo_t *ndo, void *infonode, void *_su, const u_char *bp, const char *bp2);

extern int mobility_print(ndo_t *ndo, void *infonode, void *_su, const u_char *bp, const char *bp2 _U_);

extern void ptp_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length);

extern void mpls_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length);

extern void eapol_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length);

extern void ip_demux_print(ndo_t *ndo, void *infonode, const u_char *bp, u_int length,
                    u_int ver, int fragmented, u_int ttl_hl, uint8_t nh, const u_char *iph);

extern int mptcp_print(ndo_t *ndo, void *infonode, void *psu, const u_char *cp, u_int len, u_char flags);

struct cksum_vec
{
  const uint8_t *ptr;
  int len;
};
extern uint16_t in_cksum(const struct cksum_vec *, int);
extern uint16_t in_cksum_shouldbe(uint16_t, uint16_t);

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/*
 * Locale-independent macros for testing character properties and
 * stripping the 8th bit from characters.
 *
 * Byte values outside the ASCII range are considered unprintable, so
 * both ND_ASCII_ISPRINT() and ND_ASCII_ISGRAPH() return "false" for them.
 *
 * Assumed to be handed a value between 0 and 255, i.e. don't hand them
 * a char, as those might be in the range -128 to 127.
 */
#define ND_ISASCII(c) (!((c) & 0x80)) /* value is an ASCII code point */
#define ND_ASCII_ISPRINT(c) ((c) >= 0x20 && (c) <= 0x7E)
#define ND_ASCII_ISGRAPH(c) ((c) > 0x20 && (c) <= 0x7E)
#define ND_ASCII_ISDIGIT(c) ((c) >= '0' && (c) <= '9')
#define ND_TOASCII(c) ((c) & 0x7F)

/*
 * Locale-independent macros for converting to upper or lower case.
 *
 * Byte values outside the ASCII range are not converted.  Byte values
 * *in* the ASCII range are converted to byte values in the ASCII range;
 * in particular, 'i' is upper-cased to 'I" and 'I' is lower-cased to 'i',
 * even in Turkish locales.
 */
#define ND_ASCII_TOLOWER(c) (((c) >= 'A' && (c) <= 'Z') ? (c) - 'A' + 'a' : (c))
#define ND_ASCII_TOUPPER(c) (((c) >= 'a' && (c) <= 'z') ? (c) - 'a' + 'A' : (c))

/*
 * Print out a character, filtering out the non-printable ones
 */
extern void fn_print_char(ndo_t *ndo, u_char c, char *buffer);

#endif // __NDO_H__
