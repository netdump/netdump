/**
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <setjmp.h>
#include <stdint.h>


#include "bpf.h"
#include "pcap/pcap.h"
#include "pcap/dlt.h"


#include "common.h"
#include "trace.h"
#include "sigact.h"
#include "msgcomm.h"


/**
 * @brief
 *  Pathname separator.
 * @note
 *  Use this in pathnames, but do *not* use it in URLs.
 */
#define PATH_SEPARATOR	'/'


/* Define to 1 if you have the `bpf_dump' function. */
#define HAVE_BPF_DUMP 1

/* Define to 1 if you have the declaration of `ether_ntohost' */
#define HAVE_DECL_ETHER_NTOHOST 1

/* Define to 1 if you have the `ether_ntohost' function. */
#define HAVE_ETHER_NTOHOST 1

/* Define to 1 if you have the `EVP_CIPHER_CTX_new' function. */
#define HAVE_EVP_CIPHER_CTX_NEW 1

/* Define to 1 if you have the `EVP_DecryptInit_ex' function. */
#define HAVE_EVP_DECRYPTINIT_EX 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* define if you have getrpcbynumber() */
#define HAVE_GETRPCBYNUMBER 1

/* Define to 1 if you have the `getservent' function. */
#define HAVE_GETSERVENT 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have a usable `crypto' library (-lcrypto). */
#define HAVE_LIBCRYPTO 1

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* define if the OS provides AF_INET6 and struct in6_addr */
#define HAVE_OS_IPV6_SUPPORT 1

/* if there's an os_proto.h for this platform, to use additional prototypes */
/* #undef HAVE_OS_PROTO_H */

/* Define to 1 if you have the `pcap_breakloop' function. */
#define HAVE_PCAP_BREAKLOOP 1

/* Define to 1 if you have the `pcap_create' function. */
#define HAVE_PCAP_CREATE 1

/* define if libpcap has pcap_datalink_name_to_val() */
#define HAVE_PCAP_DATALINK_NAME_TO_VAL 1

/* define if libpcap has pcap_datalink_val_to_description() */
#define HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION 1

/* Define to 1 if you have the `pcap_dump_flush' function. */
#define HAVE_PCAP_DUMP_FLUSH 1

/* Define to 1 if you have the `pcap_dump_ftell' function. */
#define HAVE_PCAP_DUMP_FTELL 1

/* Define to 1 if you have the `pcap_dump_ftell64' function. */
#define HAVE_PCAP_DUMP_FTELL64 1

/* Define to 1 if you have the `pcap_findalldevs' function. */
#define HAVE_PCAP_FINDALLDEVS 1

/* Define to 1 if you have the `pcap_free_datalinks' function. */
#define HAVE_PCAP_FREE_DATALINKS 1

/* Define to 1 if the system has the type `pcap_if_t'. */
#define HAVE_PCAP_IF_T 1

/* Define to 1 if you have the `pcap_lib_version' function. */
#define HAVE_PCAP_LIB_VERSION 1

/* define if libpcap has pcap_list_datalinks() */
#define HAVE_PCAP_LIST_DATALINKS 1

/* Define to 1 if you have the <pcap/pcap-inttypes.h> header file. */
#define HAVE_PCAP_PCAP_INTTYPES_H 1

/* Define to 1 if you have the `pcap_setdirection' function. */
#define HAVE_PCAP_SETDIRECTION 1

/* Define to 1 if you have the `pcap_set_datalink' function. */
#define HAVE_PCAP_SET_DATALINK 1

/* Define to 1 if you have the `pcap_set_immediate_mode' function. */
#define HAVE_PCAP_SET_IMMEDIATE_MODE 1

/* Define to 1 if you have the `pcap_set_tstamp_precision' function. */
#define HAVE_PCAP_SET_TSTAMP_PRECISION 1

/* Define to 1 if you have the `pcap_set_tstamp_type' function. */
#define HAVE_PCAP_SET_TSTAMP_TYPE 1

/* Define to 1 if you have the `setlinebuf' function. */
#define HAVE_SETLINEBUF 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strsep' function. */
#define HAVE_STRSEP 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if the system has the type `uintptr_t'. */
#define HAVE_UINTPTR_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if netinet/ether.h declares `ether_ntohost' */
#define NETINET_ETHER_H_DECLARES_ETHER_NTOHOST 1

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "tcpdump"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "tcpdump 4.99.5"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "tcpdump"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "4.99.5"

/* The size of `time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* define if you have ether_ntohost() and it works */
#define USE_ETHER_NTOHOST 1

/* Define as token for inline if inlining supported */
#define inline inline


/*
 * Short options.
 *
 * Note that there we use all letters for short options except for g, k,
 * o, and P, and those are used by other versions of tcpdump, and we should
 * only use them for the same purposes that the other versions of tcpdump
 * use them:
 *
 * macOS tcpdump uses -g to force non--v output for IP to be on one
 * line, making it more "g"repable;
 *
 * macOS tcpdump uses -k to specify that packet comments in pcapng files
 * should be printed;
 *
 * OpenBSD tcpdump uses -o to indicate that OS fingerprinting should be done
 * for hosts sending TCP SYN packets;
 *
 * macOS tcpdump uses -P to indicate that -w should write pcapng rather
 * than pcap files.
 *
 * macOS tcpdump also uses -Q to specify expressions that match packet
 * metadata, including but not limited to the packet direction.
 * The expression syntax is different from a simple "in|out|inout",
 * and those expressions aren't accepted by macOS tcpdump, but the
 * equivalents would be "in" = "dir=in", "out" = "dir=out", and
 * "inout" = "dir=in or dir=out", and the parser could conceivably
 * special-case "in", "out", and "inout" as expressions for backwards
 * compatibility, so all is not (yet) lost.
 */

/*
 * Set up flags that might or might not be supported depending on the
 * version of libpcap we're using.
 */


#define D_FLAG	"D"

#define I_FLAG		"I"

#define Q_FLAG "Q:"
#define Q_FLAG_USAGE " [ -Q in|out|inout ]"

/**
 * @brief
 *  getopt_long function corresponding to the short option
 */
#define SHORTOPTS "b" D_FLAG "E:hi:" I_FLAG "Lp" Q_FLAG "r:y:"


/**
 * @brief
 *  Shorten the code of the function capture_show_devices_to_display
 */
#define CAPTURE_SHORTEN_CODE(space, sp, len, fmt, ...) \
  do                                                   \
  {                                                    \
    int length = len - strlen(space);                  \
    snprintf(sp, length, fmt, ##__VA_ARGS__);          \
    sp = space + strlen(space);                        \
  } while (0);

typedef enum {
	S_SUCCESS           = 0, /* not a libnetdissect status */
	S_ERR_HOST_PROGRAM  = 1, /* not a libnetdissect status */
	S_ERR_ND_MEM_ALLOC  = 12,
	S_ERR_ND_OPEN_FILE  = 13,
	S_ERR_ND_WRITE_FILE = 14,
	S_ERR_ND_ESP_SECRET = 15
} status_exit_codes_t;

#define NORETURN_FUNCPTR __attribute((noreturn))

#define PRINTFLIKE_FUNCPTR(x,y) __attribute__((__format__(__printf__,x,y)))

typedef struct netdissect_options netdissect_options;

#define IF_PRINTER_ARGS (netdissect_options *, const struct pcap_pkthdr *, const unsigned char *)

typedef void (*if_printer) IF_PRINTER_ARGS;


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
struct netdissect_saved_packet_info {
  unsigned char *ndspi_buffer;					/* pointer to allocated buffer data */
  const unsigned char *ndspi_packetp;				/* saved beginning of data */
  const unsigned char *ndspi_snapend;				/* saved end of data */
  struct netdissect_saved_packet_info *ndspi_prev;	/* previous buffer on the stack */
};

/* 'val' value(s) for longjmp */
#define ND_TRUNCATED 1

struct netdissect_options {
	int ndo_bflag; 		/* print 4 byte ASes in ASDOT notation */
	int ndo_eflag;		/* print ethernet header */
	int ndo_fflag;		/* don't translate "foreign" IP address */
	int ndo_Kflag;		/* don't check IP, TCP or UDP checksums */
	int ndo_nflag;		/* leave addresses as numbers */
	int ndo_Nflag;		/* remove domains from printed host names */
	int ndo_qflag;		/* quick (shorter) output */
	int ndo_Sflag;		/* print raw TCP sequence numbers */
	int ndo_tflag;		/* print packet arrival time */
	int ndo_uflag;		/* Print undecoded NFS handles */
	int ndo_vflag;		/* verbosity level */
	int ndo_xflag;		/* print packet in hex */
	int ndo_Xflag;		/* print packet in hex/ASCII */
	int ndo_Aflag;		/* print packet only in ASCII observing TAB,
						* LF, CR and SPACE as graphical chars
						*/
	int ndo_Hflag;		/* dissect 802.11s draft mesh standard */
	const char *ndo_protocol;	/* protocol */
	jmp_buf ndo_early_end;	/* jmp_buf for setjmp()/longjmp() */
	void *ndo_last_mem_p;		/* pointer to the last allocated memory chunk */
	int ndo_packet_number;	/* print a packet number in the beginning of line */
	int ndo_suppress_default_print; /* don't use default_print() for unknown packet types */
	int ndo_tstamp_precision;	/* requested time stamp precision */
	const char *program_name;	/* Name of the program using the library */

	char *ndo_espsecret;
	struct sa_list *ndo_sa_list_head;  /* used by print-esp.c */
	struct sa_list *ndo_sa_default;

	char *ndo_sigsecret;		/* Signature verification secret key */

	int   ndo_packettype;	/* as specified by -T */

	int   ndo_snaplen;
	int   ndo_ll_hdr_len;	/* link-layer header length */

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
};


/**
 * @brief
 * 	Network device status
 */
typedef struct status {
	unsigned int v;
	const char *s;
} status_t;


/*
 * Maximum snapshot length.  This should be enough to capture the full
 * packet on most network interfaces.
 *
 *
 * Somewhat arbitrary, but chosen to be:
 *
 *    1) big enough for maximum-size Linux loopback packets (65549)
 *       and some USB packets captured with USBPcap:
 *
 *           https://desowin.org/usbpcap/
 *
 *       (> 131072, < 262144)
 *
 * and
 *
 *    2) small enough not to cause attempts to allocate huge amounts of
 *       memory; some applications might use the snapshot length in a
 *       savefile header to control the size of the buffer they allocate,
 *       so a size of, say, 2^31-1 might not work well.
 *
 * XXX - does it need to be bigger still?  Note that, for versions of
 * libpcap with pcap_create()/pcap_activate(), if no -s flag is specified
 * or -s 0 is specified, we won't set the snapshot length at all, and will
 * let libpcap choose a snapshot length; newer versions may choose a bigger
 * value than 262144 for D-Bus, for example.
 */
#define MAXIMUM_SNAPLEN	262144


#define INT64_T_CONSTANT(constant)	(constant##LL)


/**
 * @brief 
 *  The main function of the packet capture function
 * @param COREID
 *  COREID corresponding to the packet capture process
 * @param pname
 *  The name of the packet capture process
 * @param param
 *  Retain Parameters
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_main (unsigned int COREID, const char * pname, void * param);


/**
 * @brief
 *  The main loop of the packet capture process
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_loop (void);


/**
 * @brief 
 *  Capture process and display process information exchange
 * @param message
 *  Storing received messages
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_cmd_from_display (message_t * message);


/**
 * @brief 
 *  The capture process responds to the dispaly process
 * @param msgtype
 *  Message Type
 * @param reply
 *  Response message content
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_reply_to_display (unsigned int msgtype, const char * reply);


/**
 * @brief 
 *  Convert the command sent from the display process into a 
 *  string array that can be processed by getopt_long
 * @param command
 *  Commands with conversion
 * @param argv
 *  Store the transformed results
 * @return 
 *  Returns the number of elements in the converted string array
 */
int display_convert_cmd_to_string_array(const char * command, char * argv);

/**
 * @brief
 *  Real command parsing
 * @param command
 *  Commands to be parsed
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 *  if cmd -D it returns CP_FAD
 */
int capture_parsing_cmd_and_exec_capture(char * command);

/**
 * @brief
 *  capture process signal processing function
 * @param signo
 *  Captured signal
 */
void capture_sig_handle(void);

/**
 * @brief
 *  Calling exit after the processing function
 */
void capture_atexit_handle(void);

/**
 * @brief
 *  Resource Release
 */
void capture_resource_release(void);

/**
 * @brief
 *  Send information to the display process
 * @param msgtype
 *  Message Type
 * @param format
 *  Content Format
 */
void __capture_send_errmsg__(int msgtype, const char *format, ...);

#endif  // __CAPTURE_H__