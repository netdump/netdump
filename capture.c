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

#include "capture.h"
#include "msgcomm.h"


#if defined(HAVE_PCAP_CREATE)
/**
 * @brief
 *  buffer size
 */
static int Bflag;
#endif

#ifdef HAVE_PCAP_DUMP_FTELL64
/**
 * @brief 
 *  rotate dump files after this many bytes
 */
static int64_t Cflag;
#endif

/**
 * @brief 
 *  Keep track of which file number we're writing
 */
static int Cflag_count;

#ifdef HAVE_PCAP_FINDALLDEVS
/**
 * @brief 
 *  list available devices and exit
 */
static int Dflag;
#endif

/**
 * @brief 
 *  list available data link types and exit
 */
static int Lflag;

/**
 * @brief
 *  rotate dump files after this many seconds
 */
static int Gflag;

/**
 * @brief
 *  number of files created with Gflag rotation
 */
static int Gflag_count;

/**
 * @brief
 *  The last time_t the dump file was rotated.
 */
static time_t Gflag_time;

/**
 * @brief
 *  rfmon (monitor) mode
 */
static int Iflag;

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
/**
 * @brief 
 *  list available time stamp types
 */
static int Jflag;

/**
 * @brief
 *  packet time stamp source
 */
static int jflag = -1;
#endif

/**
 * @brief 
 *  line-buffered output
 */
static int lflag;

/**
 * @brief
 *  don't go promiscuous
 */
static int pflag;

#ifdef HAVE_PCAP_SETDIRECTION
/**
 * @brief
 *  restrict captured packet by send/receive direction
 */
static int Qflag = -1;
#endif

#ifdef HAVE_PCAP_DUMP_FLUSH
/**
 * @brief 
 *  "unbuffered" output of dump files 
 */
static int Uflag;
#endif

/**
 * @brief 
 *  recycle output files after this number of files
 */
static int Wflag;
static int WflagChars;

/**
 * @brief
 *  compress each savefile using a specified command (like gzip or bzip2)
 */
static char *zflag = NULL;

/**
 * @brief
 *  default timeout = 1000 ms = 1 s
 */
static int timeout = 1000;

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
static int immediate_mode;
#endif

static int count_mode;

static int infodelay;
static int infoprint;

char *program_name = "Netdump";

/*
 * This is exported because, in some versions of libpcap, if libpcap
 * is built with optimizer debugging code (which is *NOT* the default
 * configuration!), the library *imports*(!) a variable named dflag,
 * under the expectation that tcpdump is exporting it, to govern
 * how much debugging information to print when optimizing
 * the generated BPF code.
 *
 * This is a horrible hack; newer versions of libpcap don't import
 * dflag but, instead, *if* built with optimizer debugging code,
 * *export* a routine to set that flag.
 */
extern int dflag;
/**
 * @brief 
 *  print filter code
 */
int dflag;

/*
 * Long options.
 *
 * We do not currently have long options corresponding to all short
 * options; we should probably pick appropriate option names for them.
 *
 * However, the short options where the number of times the option is
 * specified matters, such as -v and -d and -t, should probably not
 * just map to a long option, as saying
 *
 *  tcpdump --verbose --verbose
 *
 * doesn't make sense; it should be --verbosity={N} or something such
 * as that.
 *
 * For long options with no corresponding short options, we define values
 * outside the range of ASCII graphic characters, make that the last
 * component of the entry for the long option, and have a case for that
 * option in the switch statement.
 */
#define OPTION_VERSION			                128
#define OPTION_TSTAMP_PRECISION		            129
#define OPTION_IMMEDIATE_MODE		            130
#define OPTION_PRINT			                131
#define OPTION_LIST_REMOTE_INTERFACES	        132
#define OPTION_TSTAMP_MICRO		                133
#define OPTION_TSTAMP_NANO		                134
#define OPTION_FP_TYPE			                135
#define OPTION_COUNT			                136


/**
 * @brief
 *  getopt_long function corresponding to the long option
 */
static const struct option longopts[] = {

    {"list-interfaces", no_argument, NULL, 'D'},

    {"help", no_argument, NULL, 'h'},

    {"interface", required_argument, NULL, 'i'},

#ifdef HAVE_PCAP_CREATE
    {"monitor-mode", no_argument, NULL, 'I'},
#endif

    {"dont-verify-checksums", no_argument, NULL, 'K'},

    {"list-data-link-types", no_argument, NULL, 'L'},
    
    {"no-promiscuous-mode", no_argument, NULL, 'p'},

#ifdef HAVE_PCAP_SETDIRECTION
    {"direction", required_argument, NULL, 'Q'},
#endif

    {"linktype", required_argument, NULL, 'y'},

    {NULL, 0, NULL, 0}
};


/**
 * @brief
 *  Initialize a structure of type netdissect_options
 */
struct netdissect_options Gndo = {

    .ndo_bflag = 0,
    .ndo_eflag = 1,
    .ndo_fflag = 1,/* 该选项与 -r 不能同时使用，先初始化为1，如果 cmd 命令中有 -r 选项，则将 ndo_fflag 置为0， 后期看看可不可以同时存在 */
    .ndo_Kflag = 0,
    .ndo_nflag = 1,
    .ndo_Nflag = 0,
    .ndo_qflag = 0,
    .ndo_Sflag = 1, /*将来调用print函数时看看如何可以同时获取到原始的序列号与相对的序列号*/
    .ndo_tflag = 0,
    .ndo_uflag = 0,
    .ndo_vflag = 4,
    .ndo_xflag = 1,
    .ndo_Xflag = 1,
    .ndo_Aflag = 1,
    .ndo_Hflag = 0,
    .ndo_protocol = NULL,
    .ndo_last_mem_p = NULL,
    .ndo_packet_number = 1,
    .ndo_suppress_default_print = 1,
    .ndo_tstamp_precision = 0,
    .program_name = "capture",
    .ndo_espsecret = NULL,
    .ndo_sa_list_head = NULL,
    .ndo_sa_default = NULL,
    .ndo_sigsecret = NULL,
    .ndo_packettype = 0,
    .ndo_snaplen = MAXIMUM_SNAPLEN,
    .ndo_ll_hdr_len = 0,
    /*global pointers to beginning and end of current packet (during printing) */
    .ndo_packetp = NULL,
    .ndo_snapend = NULL,
    /* stack of saved packet boundary and buffer information */
    .ndo_packet_info_stack = NULL,
    /* pointer to the if_printer function */
    .ndo_if_printer = NULL,
    /* pointer to void function to output stuff */
    .ndo_default_print = NULL,
    /* pointer to function to do regular output */
    .ndo_printf = NULL,
    /* pointer to function to output errors */
    .ndo_error = NULL,
    /* pointer to function to output warnings */
    .ndo_warning = NULL
};


/**
 * @brief
 *  Define some network device states
 */
#ifdef HAVE_PCAP_FINDALLDEVS
static const status_t status_flags[] = {
#ifdef PCAP_IF_UP
    {PCAP_IF_UP, "Up"},
#endif
#ifdef PCAP_IF_RUNNING
    {PCAP_IF_RUNNING, "Running"},
#endif
    {PCAP_IF_LOOPBACK, "Loopback"},
#ifdef PCAP_IF_WIRELESS
    {PCAP_IF_WIRELESS, "Wireless"},
#endif
    {0, NULL}};
#endif

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
int capture_main (unsigned int COREID, const char * pname, void * param) {

    GCOREID = COREID;

    if (trace_G_log) {
        fclose(trace_G_log);
    }

    TRACE_STARTUP();

    TC("Called { %s(%u, %s, %p)", __func__, COREID, pname, param);

    if (unlikely((prctl(PR_SET_NAME, pname, 0, 0, 0)) != 0)) {
        TE("Prctl set name(%s) failed", pname);
        goto label1;
    }

    if (unlikely(((sigact_register_signal_handle()) == ND_ERR))) {
        TE("Register signal handle failed");
        goto label1;
    }

    if (unlikely((capture_loop()) == ND_ERR)) {
        TE("Analysis loop startup failed");
        goto label1;
    }

label1:

    TRACE_DESTRUCTION();

    RInt(ND_OK);
}


/**
 * @brief
 *  The main loop of the packet capture process
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_loop (void) {

    TC("Called { %s(void)", __func__);

    while (1) {

        char space[1024] = {0};
        message_t * message = (message_t *)(space);

        if (unlikely((capture_cmd_from_display (message)) == ND_ERR)) {
            T(erromsg, "capture cmd from display failed");
            exit(1);
        }

        TI("     ");
        TI("message->dir: %u", message->dir);
        TI("message->msgtype: %u", message->msgtype);
        TI("message->length: %u", message->length);
        TI("message->msg: %s", message->msg);


        int argc = 0;
        char argv[128][256] = {0};

        argc = display_convert_cmd_to_string_array((const char *)(message->msg), argv);
        if (unlikely((argc < 0))) {
            TE(" Convert Command to String Array failed");
            exit(1);
        }

        TI("     ");
        int i = 0;
        for (i = 0; i < argc; i++) {
            TI(" %s", argv[i]);
        }

        capture_parsing_cmd_and_exec_capture(argc, argv);
    
        #if 0
        if (unlikely(((capture_reply_to_display(MSGCOMM_ERR, "Commad Analysis Failed")) == ND_ERR)))
        {
            TE("capture reply to display failed");
            exit(1);
        }
        getchar();
        #endif

        nd_delay_microsecond(1, 10000);

    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Capture process and display process information exchange
 * @param message
 *  Storing received messages
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int capture_cmd_from_display (message_t * message) {

    TC("Called { %s(%p)", __func__, message);

    if (unlikely((!message))) {
        TE("param error; message: %p", message);
        RInt(ND_ERR);
    }

    if (unlikely((msgcomm_message_recv(MSGCOMM_DIR_0TO1, message)) == ND_ERR)) {
        TE("msgcomm message recv failed");
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


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
int capture_reply_to_display (unsigned int msgtype, const char * reply) {

    TC("Called { %s(%u, %p)", __func__, msgtype, reply);

    if (unlikely((!reply))) {
		TE("param error; msgtype: %u; reply: %p", msgtype, reply);
		RInt(ND_ERR);
	}

	if ( unlikely(
		((msgcomm_message_send(MSGCOMM_DIR_1TO0, msgtype, reply, strlen(reply))) == ND_ERR)
	))
	{
		TE("msgcomm message send failed");
		RInt(ND_ERR);
	}

    RInt(ND_OK);
}



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
int display_convert_cmd_to_string_array(const char * command, char argv[128][256]) {

    TC("Called { %s(%s)", __func__, command);

    if (unlikely((!command) || (!argv))) {
        TE("param error; command: %p, argv: %p", command, argv);
        return -1; 
    }

    int argc = 0, index = 0, in_arg = 0;

    for (int i = 0; command[i] != '\0'; i++) {
        if (!isspace(command[i])) {
            if (!in_arg) {
                in_arg = 1;
                index = 0;
            }
            argv[argc][index++] = command[i];
        } else if (in_arg) {
            argv[argc][index] = '\0';
            argc++;
            in_arg = 0;
        }
    }

    if (in_arg) {
        argv[argc][index] = '\0';
        argc++;
    }

    RInt(argc);
}


static void
print_usage(FILE *f)
{
    (void)fprintf(f,
        "Usage: [-bc:C" D_FLAG "E:F:G:hi:" I_FLAG "KLM:pr:w:W:y:] [ -c count ]\n");
    (void)fprintf(f,
        "\t\t[ -C file_size ] [ -E algo:secret ] [ -F file ] [ -G seconds ]\n");
	(void)fprintf(f,
        "\t\t[ -i interface\n");
	(void)fprintf(f,
        "\t\t[ -M secret ]" Q_FLAG_USAGE "\n");
	(void)fprintf(f,
        "\t\t[ -r file ]\n");
	(void)fprintf(f,
        "\t\t[ -w file ] [ -W filecount ] [ -y datalinktype ]\n");
    return ;
}

static void
print_version(FILE *f)
{
    return ;
}

void
float_type_check(uint32_t in)
{
	union { /* int to float conversion buffer */
		float f;
		uint32_t i;
	} f;

	f.i = in;
	printf("%.3f\n", f.f*8/1000000);
}


static int
getWflagChars(int x)
{
	int c = 0;

	x -= 1;
	while (x > 0) {
		c += 1;
		x /= 10;
	}

	return c;
}

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
static int
tstamp_precision_from_string(const char *precision)
{
	if (strncmp(precision, "nano", strlen("nano")) == 0)
		return PCAP_TSTAMP_PRECISION_NANO;

	if (strncmp(precision, "micro", strlen("micro")) == 0)
		return PCAP_TSTAMP_PRECISION_MICRO;

	return -EINVAL;
}

static const char *
tstamp_precision_to_string(int precision)
{
	switch (precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
		return "micro";

	case PCAP_TSTAMP_PRECISION_NANO:
		return "nano";

	default:
		return "unknown";
	}
}
#endif


int
nd_have_smi_support(void)
{
#ifdef USE_LIBSMI
	return (1);
#else
	return (0);
#endif
}

/*
 * Indicates whether an SMI module has been loaded, so that we can use
 * libsmi to translate OIDs.
 */
int nd_smi_module_loaded;

int
nd_load_smi_module(const char *module, char *errbuf, size_t errbuf_size)
{
#ifdef USE_LIBSMI
	if (smiLoadModule(module) == 0) {
		snprintf(errbuf, errbuf_size, "could not load MIB module %s",
		    module);
		return (-1);
	}
	nd_smi_module_loaded = 1;
	return (0);
#else
	snprintf(errbuf, errbuf_size, "MIB module %s not loaded: no libsmi support",
	    module);
	return (-1);
#endif
}

/*
 * This array maps upper-case ASCII letters to their lower-case
 * equivalents; all other byte values are mapped to themselves,
 * so this is locale-independent and intended to be locale-independent,
 * to avoid issues with, for example, "i" and "I" not being lower-case
 * and upper-case versions of the same letter in Turkish, where
 * there are separate "i with dot" and "i without dot" letters.
 */
static const unsigned char charmap[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

int
ascii_strcasecmp(const char *s1, const char *s2)
{
	const unsigned char *cm = charmap,
			*us1 = (const unsigned char *)s1,
			*us2 = (const unsigned char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return(0);
	return(cm[*us1] - cm[*--us2]);
}

/**
 * @brief
 *  Convert to strings based on status_flag
 * @param lp
 *  Pointer to the network device status
 * @param fmt
 *  String Format
 * @param v
 *  Device flag
 * @param sep
 *  string fromat
 *
 */
char *capture_status_convert_string(const status_t *lp, const char *fmt,
                                    unsigned int v, const char *sep)
{

    TC("Called { %s(%p, %s, %u, %s)", __func__, lp, fmt, v, sep);

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
    
    
    RVoidPtr(buf);
}

/**
 * @brief
 *  Shorten the code of the function capture_show_devices_to_display
 */
#define CAPTURE_SHORTEN_CODE(msglen, msgp, fmt, ...) \
    if (msglen <= 0)                                 \
    {                                                \
        TE("Msgspace is not enough");                \
        break;                                       \
    }                                                \
    do                                               \
    {                                                \
        snprintf(msgp, msglen, fmt, ##__VA_ARGS__);  \
        msglen -= strlen(msgp);                      \
        msgp = msg + strlen(msgp);                   \
    } while (0);


/**
 * @brief
 *  Output a network device that captures packets
 */
void capture_show_devices_to_display (void) {
    
    TC("Called { %s(void)", __func__);

    pcap_if_t *dev, *devlist;
    char ebuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devlist, ebuf) < 0) {
        TE("%s", ebuf);
        if (unlikely(((capture_reply_to_display(MSGCOMM_ERR, "Find All Devs Failed")) == ND_ERR))) {
            TE("capture reply to display failed");
            exit(1);
        }
    }

    char msg[1000] = {0};
    char msgp = msg;
    short msglen = 1000;

    int i = 0;
    for (i = 0, dev = devlist; dev != NULL; i++, dev = dev->next)
    {
        
        CAPTURE_SHORTEN_CODE(msglen, msgp, "%d.%s", i + 1, dev->name);

        if (dev->description != NULL) {
            CAPTURE_SHORTEN_CODE(msglen, msgp, " (%s)", dev->description);
        }
        if (dev->flags != 0)
        {
            CAPTURE_SHORTEN_CODE(msglen, msgp, " [");

            CAPTURE_SHORTEN_CODE(msglen, msgp, "%s", capture_status_convert_string(status_flags, "none", dev->flags, ", "));

#ifdef PCAP_IF_WIRELESS
            if (dev->flags & PCAP_IF_WIRELESS)
            {
                switch (dev->flags & PCAP_IF_CONNECTION_STATUS)
                {

                    case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
                        CAPTURE_SHORTEN_CODE(msglen, msgp, ", Association status unknown");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
                        CAPTURE_SHORTEN_CODE(msglen, msgp, ", Associated");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
                        CAPTURE_SHORTEN_CODE(msglen, msgp, ", Not associated");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
                        break;
                }
            }
            else
            {
                switch (dev->flags & PCAP_IF_CONNECTION_STATUS)
                {

                    case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
                        CAPTURE_SHORTEN_CODE(msglen, msgp, ", Connection status unknown");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
                        CAPTURE_SHORTEN_CODE(msglen, msgp, ", Connected");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
                        CAPTURE_SHORTEN_CODE(msglen, msgp, ", Disconnected");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
                        break;
                }
            }
#endif
            CAPTURE_SHORTEN_CODE(msglen, msgp, "]");
        }
        CAPTURE_SHORTEN_CODE(msglen, msgp, "\n");
    }
    pcap_freealldevs(devlist);

    if (unlikely(((capture_reply_to_display(MSGCOMM_FAD, msg)) == ND_ERR)))
    {
        TE("capture reply to display failed");
        exit(1);
    }

    RVoid();
}

static pcap_t *pd;

/**
 * @brief
 *  Real command parsing
 * @param argc
 *  Number of commands
 * @param command
 *  Commands to be parsed
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 *  if cmd -D it returns CP_FAD
 */
int capture_parsing_cmd_and_exec_capture(int argc, char command[128][256]) {

    TC("Called { %s(%d, %p)", __func__, argc, command);

    int cnt = -1, op, i;
	bpf_u_int32 localnet = 0, netmask = 0;
    char *cp, *infile = NULL, *cmdbuf, *device = NULL, *RFileName = NULL, *VFileName = NULL, *WFileName = NULL;
	char *endp = NULL;
	pcap_handler callback;
	int dlt = -1;
	const char *dlt_name = NULL;
	struct bpf_program fcode;
    void (*oldhandler)(int);
    struct dump_info dumpinfo;
	unsigned char *pcap_userdata = NULL;
	char ebuf[PCAP_ERRBUF_SIZE] = {0};
	char VFileLine[PATH_MAX + 1] = {0};
	const char *username = NULL;
    const char *chroot_dir = NULL;
    char *ret = NULL;
	char *end = NULL;
    #ifdef HAVE_PCAP_FINDALLDEVS
	pcap_if_t *devlist;
	long devnum;
    #endif
    int status;
	FILE *VFile = NULL;
    int Oflag = 1;			/* run filter code optimizer */
	int yflag_dlt = -1;
	const char *yflag_dlt_name = NULL;
	int print = 0;

	netdissect_options *ndo = &Gndo;

    memset(ebuf, 0, sizeof(ebuf));

    // ndo_set_function_pointers(ndo);

    tzset();

    char * const* argv = (char * const*) command;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        
        switch (op) {
            case 'b':
                ++ndo->ndo_bflag;
                break;
            // -B 选项 对应的全局的 Bflag 被删除，后面代码中会被写死
            case 'c':
                cnt = atoi(optarg);
                if (cnt <= 0)
                    TE("invalid packet count %s", optarg);
                break;

            case 'C':
                errno = 0;
                #ifdef HAVE_PCAP_DUMP_FTELL64
                Cflag = strtoll(optarg, &endp, 10);
                #endif
                if (endp == optarg || *endp != '\0' || errno != 0 || Cflag <= 0) {
                    TE("invalid file size %s", optarg);
                }
                
                #ifdef HAVE_PCAP_DUMP_FTELL64
                if (Cflag > INT64_T_CONSTANT(0x7fffffffffffffff) / 1000000) {
                #endif
                    TE("file size %s is too large", optarg);
                }
                Cflag *= 1000000;
                break;
            // -d 删除 选项对应 dflag 变量，将来后面的代码中 dflag 永远为 0
            #ifdef HAVE_PCAP_FINDALLDEVS
            case 'D':
                Dflag++;
                break;
            #endif
            case 'L':
                Lflag++;
                break;
            // -e 选项删除了，目前在全局变量初始化时，初始化为 1
            case 'E':
                #ifndef HAVE_LIBCRYPTO
                TW("crypto code not compiled in");
                #endif
                ndo->ndo_espsecret = optarg;
                break;
            // -f 选项删除，在全局初始化时初始化为 1
            case 'F':
                infile = optarg;
                break;

            case 'G':
                Gflag = atoi(optarg);
                if (Gflag < 0)
                    TW("invalid number of seconds %s", optarg);

                /* We will create one file initially. */
                Gflag_count = 0;

                /* Grab the current time for rotation use. */
                if ((Gflag_time = time(NULL)) == (time_t)-1) {
                    TE("%s: can't get current time: %s",
                        __func__, pcap_strerror(errno));
                }
                break;

            case 'h':
                print_usage(stdout);
                exit(S_SUCCESS);
                break;
            // -H 选项直接写死了，在初始化全局变量的时候
            case 'i':
                device = optarg;
                break;

    #ifdef HAVE_PCAP_CREATE
            case 'I':
                ++Iflag;
                break;
    #endif /* HAVE_PCAP_CREATE */
            // -j jflag -J Jflag 直接删除了
            // -l 选项删除了，对应的 变量是  lflag
            case 'K':
                ++ndo->ndo_Kflag;
                break;
            // -m 选项被删除了，
            case 'M':
                /* TCP-MD5 shared secret */
    #ifndef HAVE_LIBCRYPTO
                TW("crypto code not compiled in");
    #endif
                ndo->ndo_sigsecret = optarg;
                break;
            // -n 选项被删除，全局初始化时，置为 1
            // -N 选项被删除，全局初始化为 0，使用默认的时间戳
            // -O 选项，对应的变量是 Oflag ,直接删除吧，没有用
            case 'p':
                ++pflag;
                break;
            // -q 选项直接删除吧，没有用
    #ifdef HAVE_PCAP_SETDIRECTION
            case 'Q':
                if (ascii_strcasecmp(optarg, "in") == 0)
                    Qflag = PCAP_D_IN;
                else if (ascii_strcasecmp(optarg, "out") == 0)
                    Qflag = PCAP_D_OUT;
                else if (ascii_strcasecmp(optarg, "inout") == 0)
                    Qflag = PCAP_D_INOUT;
                else
                    TE("unknown capture direction '%s'", optarg);
                break;
    #endif /* HAVE_PCAP_SETDIRECTION */

            case 'r':
                ndo->ndo_fflag = 0;
                RFileName = optarg;
                break;
            // -s 选项全局初始化时写死了，ndo->ndo_snaplen = 262144
            // -S 选项全局初始化为 1 
            // -t 选项先删除吧，觉得吧，没有啥意义，后期如果需要显示每个包之间的时间差了再说吧
            // -T 选项先删除吧，后面会有用但是目前看着比较烦
            // -u 选项删除，在初始化的时候设置成了0 ，使用默认的时间戳吧
            // -U 选项先删除吧，对应的 全部变量是 Uflag
            // -v 选项删除，全局初始化的时候已经初始化了
            // -V 显示版本信息，先删除吧，没有意义，将来会在第一个界面显示
            case 'w':
                WFileName = optarg;
                break;

            case 'W':
                Wflag = atoi(optarg);
                if (Wflag <= 0)
                    TE("invalid number of output files %s", optarg);
                WflagChars = getWflagChars(Wflag);
                break;
            // -x 选项删除，全局初始化时，已经初始化了
            // -X 选项删除，全局初始化时，已经初始化了
            case 'y':
                yflag_dlt_name = optarg;
                yflag_dlt =
                    pcap_datalink_name_to_val(yflag_dlt_name);
                if (yflag_dlt < 0)
                    TE("invalid data link type %s", yflag_dlt_name);
                break;

            // -Y 选项已删除，没有实际意义
            // -z 选项删除，没有实际意义 zflag
            // -Z 选项删除吧，没有实际意义 username
            // -# 全局初始化时，已经初始化为 1
            // OPTION_VERSION 删除，将来不显示版本信息
            // OPTION_TSTAMP_PRECISION 删除吧，使用默认的时间戳吧
            // OPTION_IMMEDIATE_MODE 选项先删除吧
            // OPTION_PRINT 选项先删除吧
            // OPTION_TSTAMP_MICRO OPTION_TSTAMP_NANO 删除吧，使用默认的 微秒
            // OPTION_FP_TYPE 先删除吧，不知道干啥的
            // OPTION_COUNT 先删除吧，不知道干啥的

            default:
                print_usage(stderr);
                exit(S_ERR_HOST_PROGRAM);
                /* NOTREACHED */
		}

    }

    // end of while(getopt_long)
    #ifdef HAVE_PCAP_FINDALLDEVS
    if (Dflag) {
        capture_show_devices_to_display();
        RInt(CP_FAD);
    }
    #endif

    if (ndo->ndo_fflag != 0 && RFileName != NULL) {
        TE("-f can not be used with -r");
        if (unlikely(((capture_reply_to_display(MSGCOMM_ERR, "-f can not be used with -r")) == ND_ERR)))
        {
            TE("capture reply to display failed");
            exit(1);
        }
        RInt(ND_ERR);
    }

    #if 0
    if ((WFileName == NULL || print) && (isatty(1) || lflag))
		timeout = 100;
    #endif

    if (RFileName != NULL)
    {
        /*
         * We don't need network access, so relinquish any set-UID
         * or set-GID privileges we have (if any).
         *
         * We do *not* want set-UID privileges when opening a
         * trace file, as that might let the user read other
         * people's trace files (especially if we're set-UID
         * root).
         */
        if (setgid(getgid()) != 0 || setuid(getuid()) != 0) {
            TW("Warning: setgid/setuid failed !\n");
        }

        pd = pcap_open_offline_with_tstamp_precision(RFileName, ndo->ndo_tstamp_precision, ebuf);

        if (pd == NULL) {
            TE("%s", ebuf);
            exit(S_ERR_HOST_PROGRAM);
        }

        dlt = pcap_datalink(pd);
        dlt_name = pcap_datalink_val_to_name(dlt);
        TI("reading from file %s", RFileName);
        if (dlt_name == NULL)
        {
            TI(", link-type %u", dlt);
        }
        else
        {
            TI(", link-type %s (%s)", dlt_name, pcap_datalink_val_to_description(dlt));
        }
        TI(", snapshot length %d\n", pcap_snapshot(pd));
#ifdef DLT_LINUX_SLL2
        if (dlt == DLT_LINUX_SLL2) {
            TI("Warning: interface names might be incorrect\n");
        }
#endif
    }
    else if (!device)
    {
        int dump_dlt = DLT_EN10MB;
        /*
         * We're dumping the compiled code without an explicit
         * device specification.  (If a device is specified, we
         * definitely want to open it to use the DLT of that device.)
         * Either default to DLT_EN10MB with a warning, or use
         * the user-specified value if supplied.
         */
        /*
         * If a DLT was specified with the -y flag, use that instead.
         */
        if (yflag_dlt != -1) {
            dump_dlt = yflag_dlt;
        }
        else {
            TW("Warning: assuming Ethernet\n");
        }
        pd = pcap_open_dead(dump_dlt, ndo->ndo_snaplen);
    }
    else
    {
        if (device == NULL)
        {
            /* No interface was specified.  Pick one. */
            /* Find the list of interfaces, and pick the first interface. */
            if (pcap_findalldevs(&devlist, ebuf) == -1) {
                TE("%s", ebuf);
                exit(S_ERR_HOST_PROGRAM);
            }
            if (devlist == NULL) {
                TE("no interfaces available for capture");
                exit(1);
            }
            device = strdup(devlist->name);
            pcap_freealldevs(devlist);

        }

        /* Try to open the interface with the specified name. */
        pd = open_interface(device, ndo, ebuf);
        if (pd == NULL)
        {
            /*
             * That failed.  If we can get a list of interfaces, and the interface name
             * is purely numeric, try to use it as a 1-based index in the list of interfaces.
             */
            devnum = parse_interface_number(device);
            if (devnum == -1)
            {
                /* It's not a number; just report the open error and fail. */
                TE("%s", ebuf);
                exit(S_ERR_HOST_PROGRAM);
            }

            /*
             * OK, it's a number; try to find the interface with that index, and try to open it.
             *
             * find_interface_by_number() exits if it couldn't be found.
             */
            device = find_interface_by_number(device, devnum);
            pd = open_interface(device, ndo, ebuf);
            if (pd == NULL) {
                TE("%s", ebuf);
                exit(S_ERR_HOST_PROGRAM);
            }

        }

        /*
         * Let user own process after capture device has been opened.
         */

        if (setgid(getgid()) != 0 || setuid(getuid()) != 0) {
            TW("Warning: setgid/setuid failed !\n");
        }

        if (Lflag) {
            show_dlts_and_exit(pd, device);
            return ND_OK;
        }
        if (yflag_dlt >= 0)
        {
#ifdef HAVE_PCAP_SET_DATALINK
            if (pcap_set_datalink(pd, yflag_dlt) < 0)
                error("%s", pcap_geterr(pd));
#else
            /*
             * We don't actually support changing the
             * data link type, so we only let them
             * set it to what it already is.
             */
            if (yflag_dlt != pcap_datalink(pd))
            {
                error("%s is not one of the DLTs supported by this device\n",
                      yflag_dlt_name);
            }
#endif
            (void)fprintf(stderr, "%s: data link type %s\n",
                          program_name,
                          pcap_datalink_val_to_name(yflag_dlt));
            (void)fflush(stderr);
        }
#if defined(DLT_LINUX_SLL2) && defined(HAVE_PCAP_SET_DATALINK)
        else
        {
            /*
             * Attempt to set default linktype to
             * DLT_LINUX_SLL2 when capturing on the
             * "any" device.
             *
             * If the attempt fails, just quietly drive
             * on; this may be a non-Linux "any" device
             * that doesn't support DLT_LINUX_SLL2.
             */
            if (strcmp(device, "any") == 0)
            {
DIAG_OFF_WARN_UNUSED_RESULT(void)
                pcap_set_datalink(pd, DLT_LINUX_SLL2);
DIAG_ON_WARN_UNUSED_RESULT
            }
        }
#endif

        i = pcap_snapshot(pd);
        if (ndo->ndo_snaplen < i)
        {
            if (ndo->ndo_snaplen != 0)
                warning("snaplen raised from %d to %d", ndo->ndo_snaplen, i);
            ndo->ndo_snaplen = i;
        }
        else if (ndo->ndo_snaplen > i)
        {
            warning("snaplen lowered from %d to %d", ndo->ndo_snaplen, i);
            ndo->ndo_snaplen = i;
        }
        if (ndo->ndo_fflag != 0)
        {
            if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0)
            {
                warning("foreign (-f) flag used but: %s", ebuf);
            }
        }
    }

    if (infile)
        cmdbuf = read_infile(infile);
    else
        cmdbuf = copy_argv(&argv[optind]);

#ifdef HAVE_PCAP_SET_OPTIMIZER_DEBUG
    pcap_set_optimizer_debug(dflag);
#endif
    if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0)
        error("%s", pcap_geterr(pd));
    if (dflag)
    {
        bpf_dump(&fcode, dflag);
        pcap_close(pd);
        free(cmdbuf);
        pcap_freecode(&fcode);
        exit_tcpdump(S_SUCCESS);
    }

#ifdef HAVE_CASPER
    if (!ndo->ndo_nflag)
        capdns = capdns_setup();
#endif /* HAVE_CASPER */

    init_print(ndo, localnet, netmask);

#ifndef _WIN32
    (void)setsignal(SIGPIPE, cleanup);
    (void)setsignal(SIGTERM, cleanup);
#endif /* _WIN32 */
    (void)setsignal(SIGINT, cleanup);
#if defined(HAVE_FORK) || defined(HAVE_VFORK)
    (void)setsignal(SIGCHLD, child_cleanup);
#endif
    /* Cooperate with nohup(1) */
#ifndef _WIN32
    /*
     * In illumos /usr/include/sys/iso/signal_iso.h causes Clang to
     * generate a -Wstrict-prototypes warning here, see [1].  The
     * __illumos__ macro is available since at least GCC 11 and Clang 13,
     * see [2].
     * 1: https://www.illumos.org/issues/16344
     * 2: https://www.illumos.org/issues/13726
     */
#ifdef __illumos__
    DIAG_OFF_STRICT_PROTOTYPES
#endif /* __illumos__ */
    if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL)
#ifdef __illumos__
        DIAG_ON_STRICT_PROTOTYPES
#endif /* __illumos__ */
            (void)
            setsignal(SIGHUP, oldhandler);
#endif /* _WIN32 */

#ifndef _WIN32
    /*
     * If a user name was specified with "-Z", attempt to switch to
     * that user's UID.  This would probably be used with sudo,
     * to allow tcpdump to be run in a special restricted
     * account (if you just want to allow users to open capture
     * devices, and can't just give users that permission,
     * you'd make tcpdump set-UID or set-GID).
     *
     * Tcpdump doesn't necessarily write only to one savefile;
     * the general only way to allow a -Z instance to write to
     * savefiles as the user under whose UID it's run, rather
     * than as the user specified with -Z, would thus be to switch
     * to the original user ID before opening a capture file and
     * then switch back to the -Z user ID after opening the savefile.
     * Switching to the -Z user ID only after opening the first
     * savefile doesn't handle the general case.
     */

    if (getuid() == 0 || geteuid() == 0)
    {
#ifdef HAVE_LIBCAP_NG
        /* Initialize capng */
        capng_clear(CAPNG_SELECT_BOTH);
        if (username)
        {
            DIAG_OFF_ASSIGN_ENUM
            capng_updatev(
                CAPNG_ADD,
                CAPNG_PERMITTED | CAPNG_EFFECTIVE,
                CAP_SETUID,
                CAP_SETGID,
                -1);
            DIAG_ON_ASSIGN_ENUM
        }
        if (chroot_dir)
        {
            DIAG_OFF_ASSIGN_ENUM
            capng_update(
                CAPNG_ADD,
                CAPNG_PERMITTED | CAPNG_EFFECTIVE,
                CAP_SYS_CHROOT);
            DIAG_ON_ASSIGN_ENUM
        }

        if (WFileName)
        {
            DIAG_OFF_ASSIGN_ENUM
            capng_update(
                CAPNG_ADD,
                CAPNG_PERMITTED | CAPNG_EFFECTIVE,
                CAP_DAC_OVERRIDE);
            DIAG_ON_ASSIGN_ENUM
        }
        capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */
        if (username || chroot_dir)
            droproot(username, chroot_dir);
    }
#endif /* _WIN32 */

    if (pcap_setfilter(pd, &fcode) < 0)
        error("%s", pcap_geterr(pd));
#ifdef HAVE_CAPSICUM
    if (RFileName == NULL && VFileName == NULL && pcap_fileno(pd) != -1)
    {
        static const unsigned long cmds[] = {BIOCGSTATS, BIOCROTZBUF};

        /*
         * The various libpcap devices use a combination of
         * read (bpf), ioctl (bpf, netmap), poll (netmap)
         * so we add the relevant access rights.
         */
        cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_EVENT);
        if (cap_rights_limit(pcap_fileno(pd), &rights) < 0 &&
            errno != ENOSYS)
        {
            error("unable to limit pcap descriptor");
        }
        if (cap_ioctls_limit(pcap_fileno(pd), cmds,
                             sizeof(cmds) / sizeof(cmds[0])) < 0 &&
            errno != ENOSYS)
        {
            error("unable to limit ioctls on pcap descriptor");
        }
    }
#endif
    if (WFileName)
    {
        /* Do not exceed the default PATH_MAX for files. */
        dumpinfo.CurrentFileName = (char *)malloc(PATH_MAX + 1);

        if (dumpinfo.CurrentFileName == NULL)
            error("malloc of dumpinfo.CurrentFileName");

        /* We do not need numbering for dumpfiles if Cflag isn't set. */
        if (Cflag != 0)
            MakeFilename(dumpinfo.CurrentFileName, WFileName, 0, WflagChars);
        else
            MakeFilename(dumpinfo.CurrentFileName, WFileName, 0, 0);

        pdd = pcap_dump_open(pd, dumpinfo.CurrentFileName);
#ifdef HAVE_LIBCAP_NG
        /* Give up CAP_DAC_OVERRIDE capability.
         * Only allow it to be restored if the -C or -G flag have been
         * set since we may need to create more files later on.
         */
        capng_update(
            CAPNG_DROP,
            (Cflag || Gflag ? 0 : CAPNG_PERMITTED) | CAPNG_EFFECTIVE,
            CAP_DAC_OVERRIDE);
        capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */
        if (pdd == NULL)
            error("%s", pcap_geterr(pd));
#ifdef HAVE_CAPSICUM
        set_dumper_capsicum_rights(pdd);
#endif
        if (Cflag != 0 || Gflag != 0)
        {
#ifdef HAVE_CAPSICUM
            /*
             * basename() and dirname() may modify their input buffer
             * and they do since FreeBSD 12.0, but they didn't before.
             * Hence use the return value only, but always assume the
             * input buffer has been modified and would need to be
             * reset before the next use.
             */
            char *WFileName_copy;

            if ((WFileName_copy = strdup(WFileName)) == NULL)
            {
                error("Unable to allocate memory for file %s",
                      WFileName);
            }
            DIAG_OFF_C11_EXTENSIONS
            dumpinfo.WFileName = strdup(basename(WFileName_copy));
            DIAG_ON_C11_EXTENSIONS
            if (dumpinfo.WFileName == NULL)
            {
                error("Unable to allocate memory for file %s",
                      WFileName);
            }
            free(WFileName_copy);

            if ((WFileName_copy = strdup(WFileName)) == NULL)
            {
                error("Unable to allocate memory for file %s",
                      WFileName);
            }
            DIAG_OFF_C11_EXTENSIONS
            char *WFileName_dirname = dirname(WFileName_copy);
            DIAG_ON_C11_EXTENSIONS
            dumpinfo.dirfd = open(WFileName_dirname,
                                  O_DIRECTORY | O_RDONLY);
            if (dumpinfo.dirfd < 0)
            {
                error("unable to open directory %s",
                      WFileName_dirname);
            }
            free(WFileName_dirname);
            free(WFileName_copy);

            cap_rights_init(&rights, CAP_CREATE, CAP_FCNTL,
                            CAP_FTRUNCATE, CAP_LOOKUP, CAP_SEEK, CAP_WRITE);
            if (cap_rights_limit(dumpinfo.dirfd, &rights) < 0 &&
                errno != ENOSYS)
            {
                error("unable to limit directory rights");
            }
            if (cap_fcntls_limit(dumpinfo.dirfd, CAP_FCNTL_GETFL) < 0 &&
                errno != ENOSYS)
            {
                error("unable to limit dump descriptor fcntls");
            }
#else /* !HAVE_CAPSICUM */
            dumpinfo.WFileName = WFileName;
#endif
            callback = dump_packet_and_trunc;
            dumpinfo.pd = pd;
            dumpinfo.pdd = pdd;
            pcap_userdata = (u_char *)&dumpinfo;
        }
        else
        {
            callback = dump_packet;
            dumpinfo.WFileName = WFileName;
            dumpinfo.pd = pd;
            dumpinfo.pdd = pdd;
            pcap_userdata = (u_char *)&dumpinfo;
        }
        if (print)
        {
            dlt = pcap_datalink(pd);
            ndo->ndo_if_printer = get_if_printer(dlt);
            dumpinfo.ndo = ndo;
        }
        else
            dumpinfo.ndo = NULL;

#ifdef HAVE_PCAP_DUMP_FLUSH
        if (Uflag)
            pcap_dump_flush(pdd);
#endif
    }
    else
    {
        dlt = pcap_datalink(pd);
        ndo->ndo_if_printer = get_if_printer(dlt);
        callback = print_packet;
        pcap_userdata = (u_char *)ndo;
    }

#ifdef SIGNAL_REQ_INFO
    /*
     * We can't get statistics when reading from a file rather
     * than capturing from a device.
     */
    if (RFileName == NULL)
        (void)setsignal(SIGNAL_REQ_INFO, requestinfo);
#endif
#ifdef SIGNAL_FLUSH_PCAP
    (void)setsignal(SIGNAL_FLUSH_PCAP, flushpcap);
#endif

    if (ndo->ndo_vflag > 0 && WFileName && RFileName == NULL && !print)
    {
        /*
         * When capturing to a file, if "--print" wasn't specified,
         *"-v" means tcpdump should, once per second,
         * "v"erbosely report the number of packets captured.
         * Except when reading from a file, because -r, -w and -v
         * together used to make a corner case, in which pcap_loop()
         * errored due to EINTR (see GH #155 for details).
         */
#ifdef _WIN32
        /*
         * https://blogs.msdn.microsoft.com/oldnewthing/20151230-00/?p=92741
         *
         * suggests that this dates back to W2K.
         *
         * I don't know what a "long wait" is, but we'll assume
         * that printing the stats could be a "long wait".
         */
        CreateTimerQueueTimer(&timer_handle, NULL,
                              verbose_stats_dump, NULL, 1000, 1000,
                              WT_EXECUTEDEFAULT | WT_EXECUTELONGFUNCTION);
        setvbuf(stderr, NULL, _IONBF, 0);
#else  /* _WIN32 */
        /*
         * Assume this is UN*X, and that it has setitimer(); that
         * dates back to UNIX 95.
         */
        struct itimerval timer;
        (void)setsignal(SIGALRM, verbose_stats_dump);
        timer.it_interval.tv_sec = 1;
        timer.it_interval.tv_usec = 0;
        timer.it_value.tv_sec = 1;
        timer.it_value.tv_usec = 1;
        setitimer(ITIMER_REAL, &timer, NULL);
#endif /* _WIN32 */
    }

    if (RFileName == NULL)
    {
        /*
         * Live capture (if -V was specified, we set RFileName
         * to a file from the -V file).  Print a message to
         * the standard error on UN*X.
         */
        if (!ndo->ndo_vflag && !WFileName)
        {
            (void)fprintf(stderr,
                          "%s: verbose output suppressed, use -v[v]... for full protocol decode\n",
                          program_name);
        }
        else
            (void)fprintf(stderr, "%s: ", program_name);
        dlt = pcap_datalink(pd);
        dlt_name = pcap_datalink_val_to_name(dlt);
        (void)fprintf(stderr, "listening on %s", device);
        if (dlt_name == NULL)
        {
            (void)fprintf(stderr, ", link-type %u", dlt);
        }
        else
        {
            (void)fprintf(stderr, ", link-type %s (%s)", dlt_name,
                          pcap_datalink_val_to_description(dlt));
        }
        (void)fprintf(stderr, ", snapshot length %d bytes\n", ndo->ndo_snaplen);
        (void)fflush(stderr);
    }

#ifdef HAVE_CAPSICUM
    cansandbox = (VFileName == NULL && zflag == NULL);
#ifdef HAVE_CASPER
    cansandbox = (cansandbox && (ndo->ndo_nflag || capdns != NULL));
#else
    cansandbox = (cansandbox && ndo->ndo_nflag);
#endif /* HAVE_CASPER */
    cansandbox = (cansandbox && (pcap_fileno(pd) != -1 ||
                                 RFileName != NULL));

    if (cansandbox && cap_enter() < 0 && errno != ENOSYS)
        error("unable to enter the capability mode");
#endif /* HAVE_CAPSICUM */

    do
    {
        status = pcap_loop(pd, cnt, callback, pcap_userdata);
        if (WFileName == NULL)
        {
            /*
             * We're printing packets.  Flush the printed output,
             * so it doesn't get intermingled with error output.
             */
            if (status == -2)
            {
                /*
                 * We got interrupted, so perhaps we didn't
                 * manage to finish a line we were printing.
                 * Print an extra newline, just in case.
                 */
                putchar('\n');
            }
            (void)fflush(stdout);
        }
        if (status == -2)
        {
            /*
             * We got interrupted. If we are reading multiple
             * files (via -V) set these so that we stop.
             */
            VFileName = NULL;
            ret = NULL;
        }
        if (status == -1)
        {
            /*
             * Error.  Report it.
             */
            (void)fprintf(stderr, "%s: pcap_loop: %s\n",
                          program_name, pcap_geterr(pd));
        }
        if (RFileName == NULL)
        {
            /*
             * We're doing a live capture.  Report the capture
             * statistics.
             */
            info(1);
        }
        pcap_close(pd);
        if (VFileName != NULL)
        {
            ret = get_next_file(VFile, VFileLine);
            if (ret)
            {
                int new_dlt;

                RFileName = VFileLine;
                pd = pcap_open_offline(RFileName, ebuf);
                if (pd == NULL)
                    error("%s", ebuf);
#ifdef HAVE_CAPSICUM
                cap_rights_init(&rights, CAP_READ);
                if (cap_rights_limit(fileno(pcap_file(pd)),
                                     &rights) < 0 &&
                    errno != ENOSYS)
                {
                    error("unable to limit pcap descriptor");
                }
#endif
                new_dlt = pcap_datalink(pd);
                if (new_dlt != dlt)
                {
                    /*
                     * The new file has a different
                     * link-layer header type from the
                     * previous one.
                     */
                    if (WFileName != NULL)
                    {
                        /*
                         * We're writing raw packets
                         * that match the filter to
                         * a pcap file.  pcap files
                         * don't support multiple
                         * different link-layer
                         * header types, so we fail
                         * here.
                         */
                        error("%s: new dlt does not match original", RFileName);
                    }

                    /*
                     * We're printing the decoded packets;
                     * switch to the new DLT.
                     *
                     * To do that, we need to change
                     * the printer, change the DLT name,
                     * and recompile the filter with
                     * the new DLT.
                     */
                    dlt = new_dlt;
                    ndo->ndo_if_printer = get_if_printer(dlt);
                    /* Free the old filter */
                    pcap_freecode(&fcode);
                    if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0)
                        error("%s", pcap_geterr(pd));
                }

                /*
                 * Set the filter on the new file.
                 */
                if (pcap_setfilter(pd, &fcode) < 0)
                    error("%s", pcap_geterr(pd));

                /*
                 * Report the new file.
                 */
                dlt_name = pcap_datalink_val_to_name(dlt);
                fprintf(stderr, "reading from file %s", RFileName);
                if (dlt_name == NULL)
                {
                    fprintf(stderr, ", link-type %u", dlt);
                }
                else
                {
                    fprintf(stderr, ", link-type %s (%s)",
                            dlt_name,
                            pcap_datalink_val_to_description(dlt));
                }
                fprintf(stderr, ", snapshot length %d\n", pcap_snapshot(pd));
            }
        }
    } while (ret != NULL);

    if (count_mode && RFileName != NULL)
        fprintf(stdout, "%u packet%s\n", packets_captured,
                PLURAL_SUFFIX(packets_captured));

    free(cmdbuf);
    pcap_freecode(&fcode);
    exit_tcpdump(status == -1 ? S_ERR_HOST_PROGRAM : S_SUCCESS);

    RInt(ND_OK);
}
