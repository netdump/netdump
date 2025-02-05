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



/**
 * @brief 
 *  list available devices and exit
 */
static int Dflag;

/**
 * @brief 
 *  list available data link types and exit
 */
static int Lflag;

/**
 * @brief
 *  rfmon (monitor) mode
 */
static int Iflag;

/**
 * @brief
 *  don't go promiscuous
 */
static int pflag;

/**
 * @brief
 *  restrict captured packet by send/receive direction
 */
static int Qflag = -1;

static pcap_t *pd = NULL;
static int supports_monitor_mode;

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
    .ndo_fflag = 0, /* 该选项与 -r 不能同时使用，先初始化为0，如果 cmd 命令中有 -r 选项，则将 ndo_fflag 置为0， 后期看看可不可以同时存在，或者是否可以不支持从文件中读取过滤规则 */
    .ndo_Kflag = 1, /* 禁用 TCP 校验和验证; 忽略 TCP 校验和错误; 初始化的时已初始化为 1 */
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
    .ndo_warning = NULL};

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

/**
 * @brief
 *  Output User Manual
 */
static void capture_usage(void)
{

    TC("Called { %s(void)", __func__);

    char space[2048] = {0};
    char * sp = space;
    int length = 2048;
    int ret = 0;

    ret = snprintf(sp, length, "Usage: [-b" D_FLAG "E:hi:" I_FLAG Q_FLAG "Lpr:y:]\n");
    if (ret == -1) {
        TE("snprintf function failed");
        exit(S_ERR_HOST_PROGRAM);
    }
    sp = space + strlen(space);
    length -= strlen(space);

    ret = snprintf(sp, length, "\t\t[ -E algo:secret ] [ -i interface]" Q_FLAG_USAGE "\n");
    if (ret == -1)
    {
        TE("snprintf function failed");
        exit(S_ERR_HOST_PROGRAM);
    }
    sp = space + strlen(space);
    length -= strlen(space);

    ret = snprintf(sp, length,"\t\t[ -r file ] [ -y datalinktype ]\n");
    if (ret == -1)
    {
        TE("snprintf function failed");
        exit(S_ERR_HOST_PROGRAM);
    }
    sp = space + strlen(space);
    length -= strlen(space);

    if (unlikely(((capture_reply_to_display(MSGCOMM_HLP, space)) == ND_ERR)))
    {
        TE("capture reply to display failed");
        exit(1);
    }

    RVoid();
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

/**
 * @brief
 *  String comparison functions
 * @param
 *  String 1
 * @param
 *  String 2
 * @return
 *  If they are equal, they return 0; 
 *  if they are not equal, they return the difference.
 */
int ascii_strcasecmp(const char *s1, const char *s2)
{
    TC("Called { %s(%p, %p)", __func__, s1, s2);

	const unsigned char *cm = charmap,
    *us1 = (const unsigned char *)s1,
    *us2 = (const unsigned char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0') {
			RInt(0);
        }
	
    RInt((int)(cm[*us1] - cm[*--us2]));
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
    char * msgp = msg;
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

/**
 * @brief
 *  capture process signal processing function
 * @param signo
 *  Captured signal
 */
void capture_signal_handle(int signo)
{

    TC("Called { %s(%d)", __func__, signo);

    #if 0
    // 目前看是没有用
    struct itimerval timer;

    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
    #endif
    pcap_breakloop(pd);

    RVoid();
}


/**
 * @brief
 *  Copy arg vector into a new buffer, concatenating arguments with spaces.
 * @param argv
 *  cmd data
 * @return
 *  Returns a pointer to the copied data.
 */
static char * capture_copy_argv(char **argv)
{

    TC("Called { %s(%p)", __func__, argv);

    char **p;
    size_t len = 0;
    char *buf;
    char *src, *dst;

    p = argv;
    if (*p == NULL)
        return 0;

    while (*p)
        len += strlen(*p++) + 1;

    buf = (char *)malloc(len);
    if (buf == NULL) {
        TE("%s: malloc", __func__);
        exit(S_ERR_HOST_PROGRAM);
    }

    p = argv;
    dst = buf;
    while ((src = *p++) != NULL)
    {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    RVoidPtr(buf);
}


/**
 * @brief 
 *  capture suport data link type (array)
 */
static int capture_support_dlt[] = {
#ifdef DLT_APPLE_IP_OVER_IEEE1394
    DLT_APPLE_IP_OVER_IEEE1394,
#endif
    DLT_ARCNET,
#ifdef DLT_ARCNET_LINUX
    DLT_ARCNET_LINUX,
#endif
    DLT_ATM_RFC1483,
#ifdef DLT_DSA_TAG_BRCM
    DLT_DSA_TAG_BRCM,
#endif
#ifdef DLT_DSA_TAG_BRCM_PREPEND
    DLT_DSA_TAG_BRCM_PREPEND,
#endif
#ifdef DLT_BLUETOOTH_HCI_H4_WITH_PHDR
    DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
#endif
#ifdef DLT_C_HDLC
    DLT_C_HDLC,
#endif
#ifdef DLT_HDLC
    DLT_HDLC,
#endif
#ifdef DLT_ATM_CLIP
    DLT_ATM_CLIP,
#endif
#ifdef DLT_CIP
    DLT_CIP,
#endif
#ifdef DLT_DSA_TAG_DSA
    DLT_DSA_TAG_DSA,
#endif
#ifdef DLT_DSA_TAG_EDSA
    DLT_DSA_TAG_EDSA,
#endif
#ifdef DLT_ENC
    DLT_ENC,
#endif
    DLT_EN10MB,
    DLT_FDDI,
#ifdef DLT_FR
    {fr_if_print, DLT_FR},
#endif
#ifdef DLT_FRELAY
    DLT_FRELAY,
#endif
#ifdef DLT_IEEE802_11
    DLT_IEEE802_11,
#endif
#ifdef DLT_IEEE802_11_RADIO_AVS
    DLT_IEEE802_11_RADIO_AVS,
#endif
#ifdef DLT_IEEE802_11_RADIO
    DLT_IEEE802_11_RADIO,
#endif
#ifdef DLT_IEEE802_15_4
    DLT_IEEE802_15_4,
#endif
#ifdef DLT_IEEE802_15_4_NOFCS
    DLT_IEEE802_15_4_NOFCS,
#endif
#ifdef DLT_IEEE802_15_4_TAP
    DLT_IEEE802_15_4_TAP,
#endif
#ifdef DLT_IP_OVER_FC
    DLT_IP_OVER_FC,
#endif
#ifdef DLT_IPNET
    DLT_IPNET,
#endif
#ifdef DLT_IPOIB
    DLT_IPOIB,
#endif
#ifdef DLT_JUNIPER_ATM1
    DLT_JUNIPER_ATM1,
#endif
#ifdef DLT_JUNIPER_ATM2
    DLT_JUNIPER_ATM2,
#endif
#ifdef DLT_JUNIPER_CHDLC
    DLT_JUNIPER_CHDLC,
#endif
#ifdef DLT_JUNIPER_ES
    DLT_JUNIPER_ES,
#endif
#ifdef DLT_JUNIPER_ETHER
    DLT_JUNIPER_ETHER,
#endif
#ifdef DLT_JUNIPER_FRELAY
    DLT_JUNIPER_FRELAY,
#endif
#ifdef DLT_JUNIPER_GGSN
    DLT_JUNIPER_GGSN,
#endif
#ifdef DLT_JUNIPER_MFR
    DLT_JUNIPER_MFR,
#endif
#ifdef DLT_JUNIPER_MLFR
    DLT_JUNIPER_MLFR,
#endif
#ifdef DLT_JUNIPER_MLPPP
    DLT_JUNIPER_MLPPP,
#endif
#ifdef DLT_JUNIPER_MONITOR
    DLT_JUNIPER_MONITOR,
#endif
#ifdef DLT_JUNIPER_PPP
    DLT_JUNIPER_PPP,
#endif
#ifdef DLT_JUNIPER_PPPOE_ATM
    DLT_JUNIPER_PPPOE_ATM,
#endif
#ifdef DLT_JUNIPER_PPPOE
    DLT_JUNIPER_PPPOE,
#endif
#ifdef DLT_JUNIPER_SERVICES
    DLT_JUNIPER_SERVICES,
#endif
#ifdef DLT_LTALK
    DLT_LTALK,
#endif
#ifdef DLT_MFR
    DLT_MFR,
#endif
#ifdef DLT_NETANALYZER
    DLT_NETANALYZER,
#endif
#ifdef DLT_NETANALYZER_TRANSPARENT
    DLT_NETANALYZER_TRANSPARENT,
#endif
#ifdef DLT_NFLOG
    DLT_NFLOG,
#endif
    DLT_NULL,
#ifdef DLT_LOOP
    DLT_LOOP,
#endif
#ifdef DLT_PFLOG
    DLT_PFLOG,
#endif
#ifdef DLT_PKTAP
    DLT_PKTAP,
#endif
#ifdef DLT_PPI
    DLT_PPI,
#endif
#ifdef DLT_PPP_BSDOS
    DLT_PPP_BSDOS,
#endif
#ifdef DLT_PPP_SERIAL
    DLT_PPP_SERIAL,
#endif
    DLT_PPP,
#ifdef DLT_PPP_PPPD
    DLT_PPP_PPPD,
#endif
#ifdef DLT_PPP_ETHER
    DLT_PPP_ETHER,
#endif
#ifdef DLT_PRISM_HEADER
    DLT_PRISM_HEADER,
#endif
    DLT_RAW,
#ifdef DLT_IPV4
    DLT_IPV4,
#endif
#ifdef DLT_IPV6
    DLT_IPV6,
#endif
#ifdef DLT_SLIP_BSDOS
    DLT_SLIP_BSDOS,
#endif
    DLT_SLIP,
#ifdef DLT_LINUX_SLL
    DLT_LINUX_SLL,
#endif
#ifdef DLT_LINUX_SLL2
    DLT_LINUX_SLL2,
#endif
#ifdef DLT_SUNATM
    DLT_SUNATM,
#endif
#ifdef DLT_SYMANTEC_FIREWALL
    DLT_SYMANTEC_FIREWALL,
#endif
    DLT_IEEE802,
#ifdef DLT_USB_LINUX
    DLT_USB_LINUX,
#endif /* DLT_USB_LINUX */
#ifdef DLT_USB_LINUX_MMAPPED
    DLT_USB_LINUX_MMAPPED,
#endif /* DLT_USB_LINUX_MMAPPED */
#ifdef DLT_VSOCK
    DLT_VSOCK,
#endif
    0,
};

/**
 * @brief
 *  Check if the type is supported in the array
 * 
 */
int capture_check_is_support_dlt (int type) {

    TC("Called { %s(%d)}", __func__, type);

    int nums = (sizeof(capture_support_dlt) / sizeof(int));
    int i = 0;
    for (i = 0; i < nums; i++) {
        if (capture_support_dlt[i] == type)
        {
            RInt(ND_OK);
        }
    }

    RInt(ND_ERR);
}


/**
 * @brief 
 *  shorten code
 */
#define CAPTURE_SHORTEN_CODE_2(msgp, length, fmt, ...)    \
    do                                                    \
    {                                                     \
        ret = snprintf(msgp, length, fmt, ##__VA_ARGS__); \
        if (ret < 0)                                      \
        {                                                 \
            TE("called snprintf failed");                 \
            exit(S_ERR_HOST_PROGRAM);                     \
        }                                                 \
        msgp = space + strlen(space);                     \
        length -= strlen(space);                          \
    } while (0);


/**
 * @brief
 *  Display data link type
 * @param pc
 *  pcap_t type pointer
 * @param device
 *  Device Name
 */
static void capture_show_datalinktype(pcap_t *pc, const char *device)
{

    TC("Called { %s(%p, %p)", __func__, pc, device);

    int n_dlts, i;
    int *dlts = 0;
    const char *dlt_name;

    n_dlts = pcap_list_datalinks(pc, &dlts);
    if (n_dlts < 0)
    {
        TE("%s", pcap_geterr(pc));
        exit(S_ERR_HOST_PROGRAM);
    }
    else if (n_dlts == 0 || !dlts)
    {
        TE("No data link types.");
        exit(S_ERR_HOST_PROGRAM);
    }

    char space[2048] = {0};
    char * msgp = space;
    int length = 2048;
    int ret = 0;

    CAPTURE_SHORTEN_CODE_2(msgp, length, "Data link types for ");
    if (supports_monitor_mode) {
        CAPTURE_SHORTEN_CODE_2(msgp, length, "%s %s", device, Iflag ? "when in monitor mode" : "when not in monitor mode");
    }
    else {
        CAPTURE_SHORTEN_CODE_2(msgp, length, "%s", device);
    }
    CAPTURE_SHORTEN_CODE_2(msgp, length, " (use option -y to set):\n");

    for (i = 0; i < n_dlts; i++)
    {
        dlt_name = pcap_datalink_val_to_name(dlts[i]);
        if (dlt_name != NULL)
        {
            CAPTURE_SHORTEN_CODE_2(msgp, length, "  %s (%s)", dlt_name, pcap_datalink_val_to_description(dlts[i]));

            if ((capture_check_is_support_dlt(dlts[i]) == ND_ERR))
            {
                CAPTURE_SHORTEN_CODE_2(msgp, length, " (printing not supported)");
            }
            CAPTURE_SHORTEN_CODE_2(msgp, length, "\n");
        }
        else
        {
            CAPTURE_SHORTEN_CODE_2(msgp, length, "  DLT %d (printing not supported)\n", dlts[i]);
        }
    }

    if (unlikely(((capture_reply_to_display(MSGCOMM_DLT, space)) == ND_ERR)))
    {
        TE("capture reply to display failed");
        exit(1);
    }

    pcap_free_datalinks(dlts);

    RVoid();
}

static pcap_t *
open_interface(const char *device, netdissect_options *ndo, char *ebuf)
{
    TC("Called { %s(%p, %p, %p)", __func__, device, ndo, ebuf);


    RVoidPtr(NULL);
}

static long
parse_interface_number(const char *device)
{
    TC("Called { %s(%p)", __func__, device);


    RULong(0UL);
}

static char *
find_interface_by_number(const char *url, long devnum)
{
    TC("Called { %s(%p, %ld)", __func__, url, devnum);


    RVoidPtr(NULL);
}

static void
print_packet(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *sp)
{

    TC("Called { %s(%p, %p, %p)", __func__, user, h, sp);

    RVoid();
}

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
int capture_parsing_cmd_and_exec_capture(int argc, char command[128][256])
{

    TC("Called { %s(%d, %p)", __func__, argc, command);

    long devnum;
    int op, i, dlt = -1, yflag_dlt = -1, status;
    char *cmdbuf = NULL, *device = NULL, *RFileName = NULL,
    *ret = NULL, ebuf[PCAP_ERRBUF_SIZE] = {0}, space[1024] = {0};
    
    const char *dlt_name = NULL, *yflag_dlt_name = NULL;
    unsigned char *pcap_userdata = NULL;
    
    pcap_if_t *devlist;
    pcap_handler callback;
    bpf_u_int32 netmask = 0;
    struct bpf_program fcode;

    netdissect_options *ndo = &Gndo;

    memset(ebuf, 0, sizeof(ebuf));

    tzset();

    char *const *argv = (char *const *)command;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1)
    {

        switch (op)
        {
            case 'b':
                ++ndo->ndo_bflag;
                break;
            
            case 'D':
                Dflag++;
                break;

            case 'L':
                Lflag++;
                break;
            
            case 'E':
                ndo->ndo_espsecret = optarg;
                break;

            case 'h':
                capture_usage();
                RInt(ND_OK);
            
            case 'i':
                device = optarg;
                break;

            case 'I':
                ++Iflag;
                break;

            case 'p':
                ++pflag;
                break;
                
            case 'Q':
                if (ascii_strcasecmp(optarg, "in") == 0) {
                    Qflag = PCAP_D_IN;
                }
                else if (ascii_strcasecmp(optarg, "out") == 0) {
                    Qflag = PCAP_D_OUT;
                }
                else if (ascii_strcasecmp(optarg, "inout") == 0) {
                    Qflag = PCAP_D_INOUT;
                }
                else {
                    memset(space, 0, 1024);
                    snprintf(space, 1024, "-Q in/out/inout; %s is error", optarg);
                    if (unlikely(((capture_reply_to_display(MSGCOMM_DLT, space)) == ND_ERR)))
                    {
                        TE("capture reply to display failed");
                        exit(1);
                    }
                    TE("-Q %s is error", optarg);
                    RInt(ND_ERR);
                }
                break;

            case 'r':
                RFileName = optarg;
                break;
            
            case 'y':
                yflag_dlt_name = optarg;
                yflag_dlt = pcap_datalink_name_to_val(yflag_dlt_name);
                if (yflag_dlt < 0) {
                    memset(space, 0, 1024);
                    snprintf(space, 1024, "-Q in/out/inout; %s is error", optarg);
                    if (unlikely(((capture_reply_to_display(MSGCOMM_DLT, space)) == ND_ERR)))
                    {
                        TE("capture reply to display failed");
                        exit(1);
                    }
                    TE("-y invalid data link type %s", yflag_dlt_name);
                    RInt(ND_ERR);
                }
                break;

            default:
                capture_usage();
                RInt(ND_ERR);
        }

    }

    // end of while(getopt_long)

    if (Dflag) {
        capture_show_devices_to_display();
        RInt(CP_FAD);
    }

    if (RFileName != NULL)
    {
        // 编写一个函数，将这些信息传输给界面显示
        // 1148 -> 1170 应该是界面的显示信息
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

        if (dlt == DLT_LINUX_SLL2) {
            TI("Warning: interface names might be incorrect\n");
        }

    }
    else if (!device)
    {
        int dump_dlt = DLT_EN10MB;
        
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

        pd = open_interface(device, ndo, ebuf);
        if (pd == NULL)
        {
            devnum = parse_interface_number(device);
            if (devnum == -1)
            {
                TE("%s", ebuf);
                exit(S_ERR_HOST_PROGRAM);
            }

            device = find_interface_by_number(device, devnum);
            pd = open_interface(device, ndo, ebuf);
            if (pd == NULL) {
                TE("%s", ebuf);
                exit(S_ERR_HOST_PROGRAM);
            }

        }
        #if 0
        if (pcap_setbuff(pd, 16 * 1024 * 1024) == -1)
        {
            TE("%s", pcap_geterr(pd));
            exit(S_ERR_HOST_PROGRAM);
        }
        #endif
        if (Lflag) {
            capture_show_datalinktype(pd, device);
            return ND_OK;
        }

        if (yflag_dlt >= 0)
        {
            if (pcap_set_datalink(pd, yflag_dlt) < 0) {
                TE("%s", pcap_geterr(pd));
                exit(S_ERR_HOST_PROGRAM);
            }

            TI("%s: data link type %s\n", program_name, pcap_datalink_val_to_name(yflag_dlt));
        }
        else
        {
            if (strcmp(device, "any") == 0)
            {
                pcap_set_datalink(pd, DLT_LINUX_SLL2);
            }
        }

        i = pcap_snapshot(pd);
        if (ndo->ndo_snaplen < i)
        {
            if (ndo->ndo_snaplen != 0)
                TW("snaplen raised from %d to %d", ndo->ndo_snaplen, i);
            ndo->ndo_snaplen = i;
        }
        else if (ndo->ndo_snaplen > i)
        {
            TW("snaplen lowered from %d to %d", ndo->ndo_snaplen, i);
            ndo->ndo_snaplen = i;
        }
    }

    cmdbuf = capture_copy_argv((char**)(&argv[optind]));

    if (pcap_compile(pd, &fcode, cmdbuf, 0, netmask) < 0) {
        TE("%s", pcap_geterr(pd));
        exit(S_ERR_HOST_PROGRAM);
    }

    if (pcap_setfilter(pd, &fcode) < 0) {
        TE("%s", pcap_geterr(pd));
        exit(S_ERR_HOST_PROGRAM);
    }

    dlt = pcap_datalink(pd);
    ndo->ndo_if_printer = NULL;
    callback = print_packet;
    pcap_userdata = (unsigned char *)ndo;

    #if 0
    // 先保留吧，目前还不知道，谁发送的这两个信号
    if (RFileName == NULL)
        (void)setsignal(SIGUSR1, requestinfo);
    (void)setsignal(SIGUSR2, flushpcap);
    #endif

    if (RFileName == NULL)
    {
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

    do
    {
        status = pcap_loop(pd, -1, callback, pcap_userdata);
        if (status == -2)
        {
            ret = NULL;
        }
        if (status == -1)
        {
            TE("%s: pcap_loop: %s\n", program_name, pcap_geterr(pd));
        }
        pcap_close(pd);
    } while (ret != NULL);
    
    free(cmdbuf);
    pcap_freecode(&fcode);
    exit(status);

    RInt(ND_OK);
}

