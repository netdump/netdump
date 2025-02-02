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

static const struct option longopts[] = {
#if defined(HAVE_PCAP_CREATE)
	{ "buffer-size", required_argument, NULL, 'B' },
#endif
	{ "list-interfaces", no_argument, NULL, 'D' },
	{ "help", no_argument, NULL, 'h' },
	{ "interface", required_argument, NULL, 'i' },
#ifdef HAVE_PCAP_CREATE
	{ "monitor-mode", no_argument, NULL, 'I' },
#endif
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	{ "time-stamp-type", required_argument, NULL, 'j' },
	{ "list-time-stamp-types", no_argument, NULL, 'J' },
#endif
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
	{ "micro", no_argument, NULL, OPTION_TSTAMP_MICRO},
	{ "nano", no_argument, NULL, OPTION_TSTAMP_NANO},
	{ "time-stamp-precision", required_argument, NULL, OPTION_TSTAMP_PRECISION},
#endif
	{ "dont-verify-checksums", no_argument, NULL, 'K' },
	{ "list-data-link-types", no_argument, NULL, 'L' },
	{ "no-optimize", no_argument, NULL, 'O' },
	{ "no-promiscuous-mode", no_argument, NULL, 'p' },
#ifdef HAVE_PCAP_SETDIRECTION
	{ "direction", required_argument, NULL, 'Q' },
#endif
	{ "snapshot-length", required_argument, NULL, 's' },
	{ "absolute-tcp-sequence-numbers", no_argument, NULL, 'S' },
#ifdef HAVE_PCAP_DUMP_FLUSH
	{ "packet-buffered", no_argument, NULL, 'U' },
#endif
	{ "linktype", required_argument, NULL, 'y' },
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
	{ "immediate-mode", no_argument, NULL, OPTION_IMMEDIATE_MODE },
#endif
	{ "relinquish-privileges", required_argument, NULL, 'Z' },
	{ "count", no_argument, NULL, OPTION_COUNT },
	{ "fp-type", no_argument, NULL, OPTION_FP_TYPE },
	{ "number", no_argument, NULL, '#' },
	{ "print", no_argument, NULL, OPTION_PRINT },
	{ "version", no_argument, NULL, OPTION_VERSION },
	{ NULL, 0, NULL, 0 }
};


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

        if (unlikely(((capture_reply_to_display(MSGCOMM_ERR, "Commad Analysis Failed")) == ND_ERR))) 
        {
            TE("capture reply to display failed");
            exit(1);
        }

        nd_delay_microsecond(1, 10000);

        getchar();

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
        "Usage: [-Abd" D_FLAG "efhH" I_FLAG J_FLAG "KlLnNOpqStu" U_FLAG "vxX#]" B_FLAG_USAGE " [ -c count ] [--count]\n");
	(void)fprintf(f,
        "\t\t[ -C file_size ] [ -E algo:secret ] [ -F file ] [ -G seconds ]\n");
	(void)fprintf(f,
        "\t\t[ -i interface ]" IMMEDIATE_MODE_USAGE j_FLAG_USAGE "\n");
	(void)fprintf(f,
        "\t\t[ -M secret ] [ --number ] [ --print ]" Q_FLAG_USAGE "\n");
	(void)fprintf(f,
        "\t\t[ -r file ] [ -s snaplen ] [ -T type ] [ --version ]\n");
	(void)fprintf(f,
        "\t\t[ -V file ] [ -w file ] [ -W filecount ] [ -y datalinktype ]\n");
    #ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
	(void)fprintf(f,
        "\t\t[ --time-stamp-precision precision ] [ --micro ] [ --nano ]\n");
    #endif
	(void)fprintf(f,
    "\t\t[ -z postrotate-command ] [ -Z user ] [ expression ]\n");
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


#if 1
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
 */
int capture_parsing_cmd (int argc, char command[128][256]) {

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

    netdissect_options Ndo;
	netdissect_options *ndo = &Ndo;

    ndo->program_name = program_name;

    tzset();

    char * const* argv = (char * const*) command;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        
        switch (op) {

            case 'a':
                /* compatibility for old -a */
                break;

            case 'A':
                ++ndo->ndo_Aflag;
                break;

            case 'b':
                ++ndo->ndo_bflag;
                break;

            #if defined(HAVE_PCAP_CREATE)
            case 'B':
                Bflag = atoi(optarg)*1024;
                if (Bflag <= 0)
                    TE("invalid packet buffer size %s", optarg);
                break;
            #endif /* defined(HAVE_PCAP_CREATE) */

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

            case 'd':
                ++dflag;
                break;

            #ifdef HAVE_PCAP_FINDALLDEVS
            case 'D':
                Dflag++;
                break;
            #endif
            case 'L':
                Lflag++;
                break;

            case 'e':
                ++ndo->ndo_eflag;
                break;

            case 'E':
                #ifndef HAVE_LIBCRYPTO
                TW("crypto code not compiled in");
                #endif
                ndo->ndo_espsecret = optarg;
                break;

            case 'f':
                ++ndo->ndo_fflag;
                break;

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

            case 'H':
                ++ndo->ndo_Hflag;
                break;

            case 'i':
                device = optarg;
                break;

    #ifdef HAVE_PCAP_CREATE
            case 'I':
                ++Iflag;
                break;
    #endif /* HAVE_PCAP_CREATE */

    #ifdef HAVE_PCAP_SET_TSTAMP_TYPE
            case 'j':
                jflag = pcap_tstamp_type_name_to_val(optarg);
                if (jflag < 0)
                    TE("invalid time stamp type %s", optarg);
                break;

            case 'J':
                Jflag++;
                break;
    #endif

            case 'l':
    
    #ifdef HAVE_SETLINEBUF
                setlinebuf(stdout);
    #else
                setvbuf(stdout, NULL, _IOLBF, 0);
    #endif
                lflag = 1;
                break;

            case 'K':
                ++ndo->ndo_Kflag;
                break;

            case 'm':
                if (nd_have_smi_support()) {
                    if (nd_load_smi_module(optarg, ebuf, sizeof(ebuf)) == -1)
                        TE("%s", ebuf);
                } else {
                    (void)fprintf(stderr, "%s: ignoring option '-m %s' ",
                            program_name, optarg);
                    (void)fprintf(stderr, "(no libsmi support)\n");
                }
                break;

            case 'M':
                /* TCP-MD5 shared secret */
    #ifndef HAVE_LIBCRYPTO
                TW("crypto code not compiled in");
    #endif
                ndo->ndo_sigsecret = optarg;
                break;

            case 'n':
                ++ndo->ndo_nflag;
                break;

            case 'N':
                ++ndo->ndo_Nflag;
                break;

            case 'O':
                Oflag = 0;
                break;

            case 'p':
                ++pflag;
                break;

            case 'q':
                ++ndo->ndo_qflag;
                ++ndo->ndo_suppress_default_print;
                break;

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
                RFileName = optarg;
                break;

            case 's':
                ndo->ndo_snaplen = (int)strtol(optarg, &end, 0);
                if (optarg == end || *end != '\0'
                    || ndo->ndo_snaplen < 0 || ndo->ndo_snaplen > MAXIMUM_SNAPLEN)
                    TE("invalid snaplen %s (must be >= 0 and <= %d)",
                        optarg, MAXIMUM_SNAPLEN);
                break;

            case 'S':
                ++ndo->ndo_Sflag;
                break;

            case 't':
                ++ndo->ndo_tflag;
                break;

            case 'T':
                if (ascii_strcasecmp(optarg, "vat") == 0)
                    ndo->ndo_packettype = PT_VAT;
                else if (ascii_strcasecmp(optarg, "wb") == 0)
                    ndo->ndo_packettype = PT_WB;
                else if (ascii_strcasecmp(optarg, "rpc") == 0)
                    ndo->ndo_packettype = PT_RPC;
                else if (ascii_strcasecmp(optarg, "rtp") == 0)
                    ndo->ndo_packettype = PT_RTP;
                else if (ascii_strcasecmp(optarg, "rtcp") == 0)
                    ndo->ndo_packettype = PT_RTCP;
                else if (ascii_strcasecmp(optarg, "snmp") == 0)
                    ndo->ndo_packettype = PT_SNMP;
                else if (ascii_strcasecmp(optarg, "cnfp") == 0)
                    ndo->ndo_packettype = PT_CNFP;
                else if (ascii_strcasecmp(optarg, "tftp") == 0)
                    ndo->ndo_packettype = PT_TFTP;
                else if (ascii_strcasecmp(optarg, "aodv") == 0)
                    ndo->ndo_packettype = PT_AODV;
                else if (ascii_strcasecmp(optarg, "carp") == 0)
                    ndo->ndo_packettype = PT_CARP;
                else if (ascii_strcasecmp(optarg, "radius") == 0)
                    ndo->ndo_packettype = PT_RADIUS;
                else if (ascii_strcasecmp(optarg, "zmtp1") == 0)
                    ndo->ndo_packettype = PT_ZMTP1;
                else if (ascii_strcasecmp(optarg, "vxlan") == 0)
                    ndo->ndo_packettype = PT_VXLAN;
                else if (ascii_strcasecmp(optarg, "pgm") == 0)
                    ndo->ndo_packettype = PT_PGM;
                else if (ascii_strcasecmp(optarg, "pgm_zmtp1") == 0)
                    ndo->ndo_packettype = PT_PGM_ZMTP1;
                else if (ascii_strcasecmp(optarg, "lmp") == 0)
                    ndo->ndo_packettype = PT_LMP;
                else if (ascii_strcasecmp(optarg, "resp") == 0)
                    ndo->ndo_packettype = PT_RESP;
                else if (ascii_strcasecmp(optarg, "ptp") == 0)
                    ndo->ndo_packettype = PT_PTP;
                else if (ascii_strcasecmp(optarg, "someip") == 0)
                    ndo->ndo_packettype = PT_SOMEIP;
                else if (ascii_strcasecmp(optarg, "domain") == 0)
                    ndo->ndo_packettype = PT_DOMAIN;
                else
                    TE("unknown packet type '%s'", optarg);
                break;

            case 'u':
                ++ndo->ndo_uflag;
                break;

    #ifdef HAVE_PCAP_DUMP_FLUSH
            case 'U':
                ++Uflag;
                break;
    #endif

            case 'v':
                ++ndo->ndo_vflag;
                break;

            case 'V':
                VFileName = optarg;
                break;

            case 'w':
                WFileName = optarg;
                break;

            case 'W':
                Wflag = atoi(optarg);
                if (Wflag <= 0)
                    TE("invalid number of output files %s", optarg);
                WflagChars = getWflagChars(Wflag);
                break;

            case 'x':
                ++ndo->ndo_xflag;
                ++ndo->ndo_suppress_default_print;
                break;

            case 'X':
                ++ndo->ndo_Xflag;
                ++ndo->ndo_suppress_default_print;
                break;

            case 'y':
                yflag_dlt_name = optarg;
                yflag_dlt =
                    pcap_datalink_name_to_val(yflag_dlt_name);
                if (yflag_dlt < 0)
                    TE("invalid data link type %s", yflag_dlt_name);
                break;

    #ifdef HAVE_PCAP_SET_PARSER_DEBUG
            case 'Y':
                {
                /* Undocumented flag */
                pcap_set_parser_debug(1);
                }
                break;
    #endif
            case 'z':
                zflag = optarg;
                break;

            case 'Z':
                username = optarg;
                break;

            case '#':
                ndo->ndo_packet_number = 1;
                break;

            case OPTION_VERSION:
                print_version(stdout);
                exit(S_SUCCESS);
                break;

    #ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
            case OPTION_TSTAMP_PRECISION:
                ndo->ndo_tstamp_precision = tstamp_precision_from_string(optarg);
                if (ndo->ndo_tstamp_precision < 0)
                    TE("unsupported time stamp precision");
                break;
    #endif

    #ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
            case OPTION_IMMEDIATE_MODE:
                immediate_mode = 1;
                break;
    #endif

            case OPTION_PRINT:
                print = 1;
                break;

    #ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
            case OPTION_TSTAMP_MICRO:
                ndo->ndo_tstamp_precision = PCAP_TSTAMP_PRECISION_MICRO;
                break;

            case OPTION_TSTAMP_NANO:
                ndo->ndo_tstamp_precision = PCAP_TSTAMP_PRECISION_NANO;
                break;
    #endif

            case OPTION_FP_TYPE:
                /*
                * Print out the type of floating-point arithmetic
                * we're doing; it's probably IEEE, unless somebody
                * tries to run this on a VAX, but the precision
                * may differ (e.g., it might be 32-bit, 64-bit,
                * or 80-bit).
                */
                float_type_check(0x4e93312d);
                return 0;

            case OPTION_COUNT:
                count_mode = 1;
                break;

            default:
                print_usage(stderr);
                exit(S_ERR_HOST_PROGRAM);
                /* NOTREACHED */
		}

    }
    


    RInt(ND_OK);
}
#endif