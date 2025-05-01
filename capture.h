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

#define _GNU_SOURCE

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
#include <stddef.h>
#include <poll.h>

#include "bpf.h"
#include "pcap/pcap.h"
#include "pcap/dlt.h"


#include "common.h"
#include "trace.h"
#include "sigact.h"
#include "msgcomm.h"
#include "ctoacomm.h"
#include "ndo.h"


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
#define PACKAGE_NAME "netdump"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "netdump 0.0.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "netdump"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.0.1"

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
 * o, and P, and those are used by other versions of netdump, and we should
 * only use them for the same purposes that the other versions of netdump
 * use them:
 *
 * macOS netdump uses -g to force non--v output for IP to be on one
 * line, making it more "g"repable;
 *
 * macOS netdump uses -k to specify that packet comments in pcapng files
 * should be printed;
 *
 * OpenBSD netdump uses -o to indicate that OS fingerprinting should be done
 * for hosts sending TCP SYN packets;
 *
 * macOS netdump uses -P to indicate that -w should write pcapng rather
 * than pcap files.
 *
 * macOS netdump also uses -Q to specify expressions that match packet
 * metadata, including but not limited to the packet direction.
 * The expression syntax is different from a simple "in|out|inout",
 * and those expressions aren't accepted by macOS netdump, but the
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


struct printer
{
	if_printer f;
	int type;
};

/* The DLT printer routines */

extern void ap1394_if_print IF_PRINTER_ARGS;
extern void arcnet_if_print IF_PRINTER_ARGS;
extern void arcnet_linux_if_print IF_PRINTER_ARGS;
extern void atm_if_print IF_PRINTER_ARGS;
extern void brcm_tag_if_print IF_PRINTER_ARGS;
extern void brcm_tag_prepend_if_print IF_PRINTER_ARGS;
extern void bt_if_print IF_PRINTER_ARGS;
extern void chdlc_if_print IF_PRINTER_ARGS;
extern void cip_if_print IF_PRINTER_ARGS;
extern void dsa_if_print IF_PRINTER_ARGS;
extern void edsa_if_print IF_PRINTER_ARGS;
extern void enc_if_print IF_PRINTER_ARGS;
extern void ether_if_print IF_PRINTER_ARGS;
extern void fddi_if_print IF_PRINTER_ARGS;
extern void fr_if_print IF_PRINTER_ARGS;
extern void ieee802_11_if_print IF_PRINTER_ARGS;
extern void ieee802_11_radio_avs_if_print IF_PRINTER_ARGS;
extern void ieee802_11_radio_if_print IF_PRINTER_ARGS;
extern void ieee802_15_4_if_print IF_PRINTER_ARGS;
extern void ieee802_15_4_tap_if_print IF_PRINTER_ARGS;
extern void ipfc_if_print IF_PRINTER_ARGS;
extern void ipnet_if_print IF_PRINTER_ARGS;
extern void ipoib_if_print IF_PRINTER_ARGS;
extern void juniper_atm1_if_print IF_PRINTER_ARGS;
extern void juniper_atm2_if_print IF_PRINTER_ARGS;
extern void juniper_chdlc_if_print IF_PRINTER_ARGS;
extern void juniper_es_if_print IF_PRINTER_ARGS;
extern void juniper_ether_if_print IF_PRINTER_ARGS;
extern void juniper_frelay_if_print IF_PRINTER_ARGS;
extern void juniper_ggsn_if_print IF_PRINTER_ARGS;
extern void juniper_mfr_if_print IF_PRINTER_ARGS;
extern void juniper_mlfr_if_print IF_PRINTER_ARGS;
extern void juniper_mlppp_if_print IF_PRINTER_ARGS;
extern void juniper_monitor_if_print IF_PRINTER_ARGS;
extern void juniper_ppp_if_print IF_PRINTER_ARGS;
extern void juniper_pppoe_atm_if_print IF_PRINTER_ARGS;
extern void juniper_pppoe_if_print IF_PRINTER_ARGS;
extern void juniper_services_if_print IF_PRINTER_ARGS;
extern void ltalk_if_print IF_PRINTER_ARGS;
extern void mfr_if_print IF_PRINTER_ARGS;
extern void netanalyzer_if_print IF_PRINTER_ARGS;
extern void netanalyzer_transparent_if_print IF_PRINTER_ARGS;
extern void nflog_if_print IF_PRINTER_ARGS;
extern void null_if_print IF_PRINTER_ARGS;
extern void pflog_if_print IF_PRINTER_ARGS;
extern void pktap_if_print IF_PRINTER_ARGS;
extern void ppi_if_print IF_PRINTER_ARGS;
extern void ppp_bsdos_if_print IF_PRINTER_ARGS;
extern void ppp_hdlc_if_print IF_PRINTER_ARGS;
extern void ppp_if_print IF_PRINTER_ARGS;
extern void pppoe_if_print IF_PRINTER_ARGS;
extern void prism_if_print IF_PRINTER_ARGS;
extern void raw_if_print IF_PRINTER_ARGS;
extern void sl_bsdos_if_print IF_PRINTER_ARGS;
extern void sl_if_print IF_PRINTER_ARGS;
extern void sll2_if_print IF_PRINTER_ARGS;
extern void sll_if_print IF_PRINTER_ARGS;
extern void sunatm_if_print IF_PRINTER_ARGS;
extern void symantec_if_print IF_PRINTER_ARGS;
extern void token_if_print IF_PRINTER_ARGS;
extern void unsupported_if_print IF_PRINTER_ARGS;
extern void usb_linux_48_byte_if_print IF_PRINTER_ARGS;
extern void usb_linux_64_byte_if_print IF_PRINTER_ARGS;
extern void vsock_if_print IF_PRINTER_ARGS;


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
void capture_send_errmsg(int msgtype, const char *format, ...);

#endif  // __CAPTURE_H__