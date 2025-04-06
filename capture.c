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
static int pflag = 0;

/**
 * @brief
 *  restrict captured packet by send/receive direction
 */
static int Qflag = -1;

/**
 * @brief
 *  Whether to support monitoring mode
 */
static int supports_monitor_mode;

/**
 * @brief
 *  default timeout = 1000 ms = 1 s
 *  userful for function pcap_set_timeout 
 */
static int timeout = 1000;

/**
 * @brief
 *  Cache size
 *  userful for function 
 */
static int Bflag = (16 * 1024 * 1024);

/**
 * @brief
 *  Timestamp accuracy
 */
#define CAPTURE_TSTAMP_PRECISION    0
static int tstamp_precision = CAPTURE_TSTAMP_PRECISION;

/**
 * @brief
 *  Process name
 */
char *program_name = "netdump";

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
/**
 * @brief 
 *  print filter code
 */
int dflag;

/**
 * @brief
 *  Global pcap_t pointer
 */
static pcap_t *pd = NULL;

/**
 * @brief
 *  for "pcap_compile()", "pcap_setfilter()"
 */
struct bpf_program fcode;

/**
 * @brief
 *  Pointer to memory used for communication
 */
static char * space = NULL;

/**
 * @brief
 *  Instruction-specific memory
 */
static char * cmdmem = NULL;

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
    .ndo_tstamp_precision = CAPTURE_TSTAMP_PRECISION,
    .program_name = "netdump",
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

#if 0
    /* pointer to void function to output stuff */
    .ndo_default_print = NULL,
    /* pointer to function to do regular output */
    .ndo_printf = NULL,
    /* pointer to function to output errors */
    .ndo_error = NULL,
    /* pointer to function to output warnings */
    .ndo_warning = NULL
#endif
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

    space = msgcomm_G_sapce;

    cmdmem = msgcomm_G_cmdmem;

    if (unlikely((prctl(PR_SET_NAME, pname, 0, 0, 0)) != 0)) {
        TE("Prctl set name(%s) failed", pname);
        goto label1;
    }

    if (unlikely(((sigact_register_signal_handle()) == ND_ERR))) {
        TE("Register signal handle failed");
        goto label1;
    }

    ctoacomm_memory_load();

    if (unlikely((capture_loop()) == ND_ERR)) {
        TE("Analysis loop startup failed");
        goto label1;
    }

label1:

    capture_resource_release();

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

        ctoacomm_memory_load();

        G_ctoa_shm_mem_wp = CTOACOMM_SHM_BASEADDR;

        memset(cmdmem, 0, MSGCOMM_CMDMEM_SIZE);
        message_t *message = (message_t *)(cmdmem);

        if (unlikely((capture_cmd_from_display (message)) == ND_ERR)) {
            T(erromsg, "capture cmd from display failed");
            exit(1);
        }

        TI("     ");
        TI("message->dir: %u", message->dir);
        TI("message->msgtype: %u", message->msgtype);
        TI("message->length: %u", message->length);
        TI("message->msg: %s", message->msg);

        #if 0
        // 还未实现
        G_ctos_shm_mem_cursor = G_ctoa_shm_mem;
        memset((void *)G_cp_aa_shared_addr_info, 0, MSGCOMM_PKTPTRARR_SIZE);
        #endif

        msgcomm_zero_variable(msgcomm_st_NObytes);
        msgcomm_zero_variable(msgcomm_st_NOpackages);

        capture_parsing_cmd_and_exec_capture((char *)(cmdmem + sizeof(message_t)));
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
int display_convert_cmd_to_string_array(const char * command, char * argv) {

    TC("Called { %s(%s, %p)", __func__, command, argv);

    if (unlikely((!command) || (!argv))) {
        TE("param error; command: %p, argv: %p", command, argv);
        return -1; 
    }

    char(*pointer)[128][256] = (char(*)[128][256])argv;

    int argc = 0, index = 0, in_arg = 0;

    for (int i = 0; command[i] != '\0'; i++) {
        if (!isspace(command[i])) {
            if (!in_arg) {
                in_arg = 1;
                index = 0;
            }
            (*pointer)[argc][index++] = command[i];
        } else if (in_arg) {
            (*pointer)[argc][index] = '\0';
            argc++;
            in_arg = 0;
        }
    }

    if (in_arg) {
        (*pointer)[argc][index] = '\0';
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

    memset(space, 0, MSGCOMM_SPACE_SIZE);
    char * sp = space;
    int len = MSGCOMM_SPACE_SIZE;

    CAPTURE_SHORTEN_CODE(space, sp, len, "\n\tUsage: \n\t[-b" D_FLAG "E:hi:" I_FLAG Q_FLAG "Lpr:y:]\n");

    CAPTURE_SHORTEN_CODE(space, sp, len, "\t[ -E algo:secret ] [ -i interface]" Q_FLAG_USAGE "\n");

    CAPTURE_SHORTEN_CODE(space, sp, len, "\t[ -r file ] [ -y datalinktype ]\n");

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
 *  Output a network device that captures packets
 */
void capture_show_devices_to_display (void) {
    
    TC("Called { %s(void)", __func__);

    pcap_if_t *dev, *devlist;
    char ebuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devlist, ebuf) < 0) {
        TE("%s", ebuf);
        capture_send_errmsg(MSGCOMM_ERR, "%s", ebuf);
    }

    memset(space, 0, MSGCOMM_SPACE_SIZE);
    char *sp = space;
    int len = MSGCOMM_SPACE_SIZE;

    int i = 0;
    for (i = 0, dev = devlist; dev != NULL; i++, dev = dev->next)
    {

        CAPTURE_SHORTEN_CODE(space, sp, len, "\n\t%d.%s", i + 1, dev->name);

        if (dev->description != NULL) {
            CAPTURE_SHORTEN_CODE(space, sp, len, " (%s)", dev->description);
        }
        if (dev->flags != 0)
        {
            CAPTURE_SHORTEN_CODE(space, sp, len, " [");

            CAPTURE_SHORTEN_CODE(space, sp, len, "%s", capture_status_convert_string(status_flags, "none", dev->flags, ", "));

#ifdef PCAP_IF_WIRELESS
            if (dev->flags & PCAP_IF_WIRELESS)
            {
                switch (dev->flags & PCAP_IF_CONNECTION_STATUS)
                {

                    case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
                        CAPTURE_SHORTEN_CODE(space, sp, len, ", Association status unknown");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
                        CAPTURE_SHORTEN_CODE(space, sp, len, ", Associated");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
                        CAPTURE_SHORTEN_CODE(space, sp, len, ", Not associated");
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
                        CAPTURE_SHORTEN_CODE(space, sp, len, ", Connection status unknown");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
                        CAPTURE_SHORTEN_CODE(space, sp, len, ", Connected");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
                        CAPTURE_SHORTEN_CODE(space, sp, len, ", Disconnected");
                        break;

                    case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
                        break;
                }
            }
#endif
            CAPTURE_SHORTEN_CODE(space, sp, len, "]");
        }
        //CAPTURE_SHORTEN_CODE(space, sp, len, "\n");
    }

    pcap_freealldevs(devlist);

    TI("%s", space);

    if (unlikely(((capture_reply_to_display(MSGCOMM_FAD, space)) == ND_ERR)))
    {
        TE("capture reply to display failed");
        exit(1);
    }

    RVoid();
}

/**
 * @brief
 *  Resource Release
 */
void capture_resource_release(void)
{

    TC("Called {%s(void)", __func__);

    if (pd)
    {
        pcap_close(pd);
    }

    
    pcap_freecode(&fcode);

    RVoid();
}

/**
 * @brief
 *  capture process signal processing function
 */
void capture_sig_handle(void)
{

    TC("Called { %s(void)", __func__);

    capture_resource_release();

    RVoid();
}


/**
 * @brief
 *  Calling exit after the processing function
 */
void capture_atexit_handle(void) {

    TC("Called { %s(void)", __func__);

    capture_resource_release();

    TRACE_DESTRUCTION();

    return ;
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
    char *src, *dst;

    p = argv;
    if (*p == NULL) {
        TE("param is null");
        RVoidPtr(NULL);
    }

    while (*p)
        len += strlen(*p++) + 1;

    if (!len) {
        TE("The sum of all string lengths is zero");
        RVoidPtr(NULL);
    }

    p = argv;
    dst = msgcomm_G_cmdbuf;
    while ((src = *p++) != NULL)
    {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    RVoidPtr(msgcomm_G_cmdbuf);
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
        capture_send_errmsg(MSGCOMM_ERR, "%s", pcap_geterr(pc));
        RVoid();
    }
    else if (n_dlts == 0 || !dlts)
    {
        TE("No data link types.");
        capture_send_errmsg(MSGCOMM_ERR, "No data link types.");
        RVoid();
    }

    memset(space, 0, MSGCOMM_SPACE_SIZE);
    char * sp = space;
    int len = MSGCOMM_SPACE_SIZE;

    CAPTURE_SHORTEN_CODE(space, sp, len, "\n\tData link types for ");
    if (supports_monitor_mode) {
        CAPTURE_SHORTEN_CODE(space, sp, len, "%s %s", device, Iflag ? "when in monitor mode" : "when not in monitor mode");
    }
    else {
        CAPTURE_SHORTEN_CODE(space, sp, len, "%s", device);
    }
    CAPTURE_SHORTEN_CODE(space, sp, len, " (use option -y to set):\n");

    for (i = 0; i < n_dlts; i++)
    {
        dlt_name = pcap_datalink_val_to_name(dlts[i]);
        if (dlt_name != NULL)
        {
            CAPTURE_SHORTEN_CODE(space, sp, len, "\t%s (%s)", dlt_name, pcap_datalink_val_to_description(dlts[i]));

            if ((capture_check_is_support_dlt(dlts[i]) == ND_ERR))
            {
                CAPTURE_SHORTEN_CODE(space, sp, len, " (printing not supported)");
            }
            CAPTURE_SHORTEN_CODE(space, sp, len, "\n");
        }
        else
        {
            CAPTURE_SHORTEN_CODE(space, sp, len, "  DLT %d (printing not supported)\n", dlts[i]);
        }
    }

    TI("%s", space);

    if (unlikely(((capture_reply_to_display(MSGCOMM_DLT, space)) == ND_ERR)))
    {
        TE("capture reply to display failed");
        exit(1);
    }

    pcap_free_datalinks(dlts);

    RVoid();
}

/**
 * @brief
 *  Convert timestamp to string
 * @param precision
 *  Timestamp Type
 * @return
 *  timestamp string
 */
static const char * capture_tstamp_precision_to_string(int precision)
{

    TC("Called %s(%d)", __func__, precision);

    switch (precision)
    {
        case PCAP_TSTAMP_PRECISION_MICRO:
            RVoidPtr((void *)"micro");

        case PCAP_TSTAMP_PRECISION_NANO:
            RVoidPtr((void *)"nano");

        default:
            RVoidPtr((void *)"unknown");
    }

    RVoidPtr(NULL);
}

/**
 * @brief
 *  Only used by the capture_open_interface function
 */
#define capture_oi_error_handle(ebuf, pc, format, ...)              \
    do                                                              \
    {                                                               \
        memset(ebuf, 0, PCAP_ERRBUF_SIZE);                          \
        snprintf(ebuf, PCAP_ERRBUF_SIZE, format, ##__VA_ARGS__);    \
        TE("%s", ebuf);                                             \
        pcap_close(pc);                                             \
        pd = NULL;                                                  \
        RVoidPtr(NULL);                                             \
    } while (0);                                                    \

/**
 * @brief
 *  Open a device interface
 * @param device
 *  Device name string
 * @param ndo
 *  netdissect_options structure type pointer
 * @param ebuf
 *  Space for error messages
 * @return
 *  Returns a pcap_t pointer on success, NULL on failure
 */
static pcap_t * capture_open_interface(const char *device, netdissect_options *ndo, char *ebuf)
{
    TC("Called { %s(%p, %p, %p)", __func__, device, ndo, ebuf);

    pcap_t *pc;
    int status;
    char *cp;

    pc = pcap_create(device, ebuf);
    if (pc == NULL)
    {
        if (strstr(ebuf, "No such device") != NULL) {
            TE("No such device");
            RVoidPtr(NULL);
        }
        TE("%s", ebuf);
        RVoidPtr(NULL);
    }

    status = pcap_set_tstamp_precision(pc, tstamp_precision);
    if (status != 0) {
        capture_oi_error_handle(ebuf, pc, 
                "%s: Can't set %s second time stamp precision: %s", 
                device,
                capture_tstamp_precision_to_string(tstamp_precision),
                pcap_statustostr(status));
    }

    if (pcap_can_set_rfmon(pc) == 1) {
        supports_monitor_mode = 1;
    }
    else {
        supports_monitor_mode = 0;
    }

    status = pcap_set_snaplen(pc, MAXIMUM_SNAPLEN);
    if (status != 0) {
        capture_oi_error_handle(ebuf, pc, "%s: Can't set snapshot length: %s", device, pcap_statustostr(status));
    }

    status = pcap_set_promisc(pc, !pflag);
    if (status != 0) {
        capture_oi_error_handle(ebuf, pc, "%s: Can't set promiscuous mode: %s", device, pcap_statustostr(status));
    }

    if (Iflag)
    {
        status = pcap_set_rfmon(pc, 1);
        if (status != 0) {
            capture_oi_error_handle(ebuf, pc, "%s: Can't set monitor mode: %s", device, pcap_statustostr(status));
        }
    }

    status = pcap_set_timeout(pc, timeout);
    if (status != 0) {
        capture_oi_error_handle(ebuf, pc, "%s: pcap_set_timeout failed: %s", device, pcap_statustostr(status));
    }

    status = pcap_set_buffer_size(pc, Bflag);
    if (status != 0) {
        capture_oi_error_handle(ebuf, pc, "%s: Can't set buffer size: %s", device, pcap_statustostr(status));
    }

    status = pcap_activate(pc);
    if (status < 0)
    {
        TE("pcap_active failed");
        cp = pcap_geterr(pc);
        if (status == PCAP_ERROR) {
            capture_oi_error_handle(ebuf, pc, "%s", cp);
        }
        else if (status == PCAP_ERROR_NO_SUCH_DEVICE)
        {
            snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: %s\n\t(%s)", device, pcap_statustostr(status), cp);
        }
        else if (status == PCAP_ERROR_PERM_DENIED && *cp != '\0') {
            capture_oi_error_handle(ebuf, pc, "%s: %s\n\t(%s)", device, pcap_statustostr(status), cp);
        }
        else {
            capture_oi_error_handle(ebuf, pc,"%s: %s", device, pcap_statustostr(status));
        }
        pcap_close(pc);
        pd = NULL;
        return (NULL);
    }
    else if (status > 0)
    {
        cp = pcap_geterr(pc);
        if (status == PCAP_WARNING) {
            TW("%s", cp);
        }
        else if (status == PCAP_WARNING_PROMISC_NOTSUP && *cp != '\0') {
            TW("%s: %s\n(%s)", device, pcap_statustostr(status), cp);
        }
        else {
            TW("%s: %s", device, pcap_statustostr(status));
        }
    }

    if (Qflag != -1)
    {
        status = pcap_setdirection(pc, Qflag);
        if (status != 0) {
            capture_oi_error_handle(ebuf, pc,"%s: pcap_setdirection() failed: %s", device, pcap_geterr(pc));
        }
    }

    TI("pcap_snapshot return value :%d", pcap_snapshot(pc));

    RVoidPtr((void *)pc);
}

/**
 * @brief
 *  
 * @param device
 *  Device name string
 * @return 
 *  
 */
static long capture_parse_interface_number(const char *device)
{
    TC("Called { %s(%p)", __func__, device);

    const char *p;
    long devnum;
    char *end;

    /*
     * Search for a colon, terminating any scheme at the beginning
     * of the device.
     */
    p = strchr(device, ':');
    if (p != NULL)
    {
        /*
         * We found it.  Is it followed by "//"?
         */
        p++; /* skip the : */
        if (strncmp(p, "//", 2) == 0)
        {
            /*
             * Yes.  Search for the next /, at the end of the
             * authority part of the URL.
             */
            p += 2; /* skip the // */
            p = strchr(p, '/');
            if (p != NULL)
            {
                /*
                 * OK, past the / is the path.
                 */
                device = p + 1;
            }
        }
    }
    devnum = strtol(device, &end, 10);
    if (device != end && *end == '\0')
    {
        /*
         * It's all-numeric, but is it a valid number?
         */
        if (devnum <= 0)
        {
            /*
             * No, it's not an ordinal.
             */
            TE("Invalid adapter index %s", device);
            RLong(-1L);
        }
        RLong(devnum);
    }
    else
    {
        /*
         * It's not all-numeric; return -1, so our caller
         * knows that.
         */
        RLong(-1L);
    }

    RLong(0L);
}

/**
 * @brief
 *  Find the interface name based on the device number
 * @param url
 *  Device Name
 * @param devnum
 *  Device Number
 * @return
 *  
 */
static char * capture_find_interface_by_number(const char *url, long devnum)
{
    TC("Called { %s(%p, %ld)", __func__, url, devnum);

    pcap_if_t *dev, *devlist;
    long i;
    char ebuf[PCAP_ERRBUF_SIZE];
    char *device;
    int status;

    status = pcap_findalldevs(&devlist, ebuf);
    if (status < 0) {
        TE("%s", ebuf);
        RVoidPtr(NULL);
    }
    /*
     * Look for the devnum-th entry in the list of devices (1-based).
     */
    for (i = 0, dev = devlist; i < devnum - 1 && dev != NULL; i++, dev = dev->next);

    if (dev == NULL)
    {
        pcap_freealldevs(devlist);
        TE("Invalid adapter index %ld: only %ld interfaces found", devnum, i);
        RVoidPtr(NULL);
    }

    device = strdup(dev->name);
    pcap_freealldevs(devlist);
    
    RVoidPtr((void *)device);
}


/**
 * @brief
 *  Copy data to shared memory
 * @param user
 *  Pointer to pcap_t type
 * @param h
 *  Generic per-packet information
 * @param sp
 *  Pointer to data
 */
static void capture_copy_packet(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *sp)
{

    TC("Called { %s(%p, %p, %p)", __func__, user, h, sp);

    unsigned int tmp = 0;
    int invalid_header = 0;
    msgcomm_receive_status_value(msgcomm_st_runflag, tmp);
    if (MSGCOMM_ST_PAUSE == tmp)
        return ;

    if (h->caplen == 0)
    {
        invalid_header = 1;
        TI("[Invalid header: caplen==0");
    }
    if (h->len == 0)
    {
        if (!invalid_header)
        {
            invalid_header = 1;
            TI("[Invalid header:");
        }
        else
            TI(",");
        TI(" len==0");
    }
    else if (h->len < h->caplen)
    {
        if (!invalid_header)
        {
            invalid_header = 1;
            TI("[Invalid header:");
        }
        else
            TI(",");
        TI(" len(%u) < caplen(%u)", h->len, h->caplen);
    }
    if (h->caplen > MAXIMUM_SNAPLEN)
    {
        if (!invalid_header)
        {
            invalid_header = 1;
            TI("[Invalid header:");
        }
        else
            TI(",");
        TI(" caplen(%u) > %u", h->caplen, MAXIMUM_SNAPLEN);
    }
    if (h->len > MAXIMUM_SNAPLEN)
    {
        if (!invalid_header)
        {
            invalid_header = 1;
            TI("[Invalid header:");
        }
        else
            TI(",");
        TI(" len(%u) > %u", h->len, MAXIMUM_SNAPLEN);
    }
    if (invalid_header)
    {
        TI("]\n");
        RVoid();
    }

    G_ctoa_shm_mem_wp = (void *)CTOACOMM_ADDR_ALIGN(G_ctoa_shm_mem_wp);

    TI("pre wp address: %p", G_ctoa_shm_mem_wp);

    datastore_t * ds = (datastore_t *)(G_ctoa_shm_mem_wp);
    ds->pkthdr = *h;
    TI("h->ts.tv_sec: %lu, h->ts.tv_usec: %lu, h->caplen: %u, h->len: %u", h->ts.tv_sec, h->ts.tv_usec, h->caplen, h->len);
    memcpy(ds->data, sp, h->len);
    G_ctoa_shm_mem_wp += (sizeof(struct pcap_pkthdr) + h->len);
    TI("after wp address: %p; sizeof(struct pcap_pkthdr): %lu; h->len: %u", G_ctoa_shm_mem_wp, sizeof(struct pcap_pkthdr), h->len);

    __builtin_prefetch((void *)CTOACOMM_ADDR_ALIGN(G_ctoa_shm_mem_wp), 1, 3);

    msgcomm_increase_data_value(msgcomm_st_NOpackages, 1);
    msgcomm_increase_data_value(msgcomm_st_NObytes, h->len);

    RVoid();
}


/**
 * @brief
 *  Send information to the display process
 * @param msgtype
 *  Message Type
 * @param format
 *  Content Format
 */
void capture_send_errmsg(int msgtype, const char *format, ...)
{
    
    TC("Called { %s(%d, %s)", __func__, msgtype, format);

    memset(space, 0, MSGCOMM_SPACE_SIZE);

    va_list args;
    va_start(args, format);
    vsnprintf(space, MSGCOMM_SPACE_SIZE, format, args);
    va_end(args);

    if (unlikely(((capture_reply_to_display(msgtype, space)) == ND_ERR)))
    {
        TE("capture reply to display failed");
        exit(1);
    }

    RVoid();
}


/**
 * @brief
 *  Check whether the passed parameters meet the requirements
 * @param command
 *  The string to be tested
 */
int capture_check_command_meet_requirement (const char * command) {

    TC("Called { %s(%s)", __func__, command);

    int len = (int)strlen(command), i = 0, j = 0;

    char * faddr = NULL, * saddr = NULL, * strp = (char *)command;

    for (i = 0; i < len; i++) 
    {
        if (strp[i] == '-' && faddr == NULL) {
            faddr = strp + i;
        }

        if ((strp[i] == ' ' || (i == (len - 1))) && saddr == NULL && faddr)
        {
            saddr = strp + i;
        }

        if (faddr && saddr) {
            if ((int)(saddr - faddr) == 2) 
            {
                TI("*faddr: %c; *(faddr+1): %c; faddr: %p, saddr: %p", *faddr, *(faddr + 1), faddr, saddr);
                TI("\n");
                if (!(strchr(SHORTOPTS, *(faddr + 1)))) {
                    RInt(ND_ERR);
                }
            }
            else if ((int)(saddr - faddr) > 2)
            {
                TI("(sizeof(longopts) / sizeof(struct option)): %ld", (sizeof(longopts) / sizeof(struct option)));
                for (j = 0; j < ((sizeof(longopts) / sizeof(struct option)) - 1); j++)
                {
                    if (!(strncmp((faddr + 2), longopts[j].name, strlen(longopts[j].name))))
                    {
                        break;
                    }
                }
                if (j == (sizeof(longopts) / sizeof(struct option)))
                {
                    RInt(ND_ERR);
                }
            }
            else 
            {
                TE("Unkown Error");
                RInt(ND_ERR);
            }
            faddr = NULL;
            saddr = NULL;
        }
    }

    RInt(ND_OK);
}

/**
 * @brief
 *  Converts a command in string format to a command in pointer array format
 * @param command
 *  Commands in string format
 * @return
 *  Returns the number of converted
 */
int capture_convert_command_to_argv(char * command) 
{

    TC("called { %s(%s)", __func__, command);

    int tmp = strlen(command), nums = 0, i = 0;

    memset(msgcomm_G_argv, 0, MSGCOMM_ARGV_SIZE);

    char **argv = (char **)msgcomm_G_argv, *tmpp = NULL;

    for (i = 0; i < tmp; i++)
    {
        if (!tmpp)
        {
            tmpp = command + i;
        }
        if (command[i] == '\0')
        {
            break;
        }
        if (command[i] == ' ')
        {
            argv[nums++] = tmpp;
            command[i] = '\0';
            tmpp = NULL;
        }
        if ((i == (tmp - 1)) && tmpp)
        {
            argv[nums++] = tmpp;
        }
    }

    TI("nums: %d", nums);
    for (i = 0; i < nums; i++)
    {
        TI("argv[%d]: %s", i, argv[i]);
        TI("nums: %d; i: %d", nums, i);
    }

    RInt(nums);
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
int capture_parsing_cmd_and_exec_capture(char * command)
{

    TC("Called { %s(%p)", __func__, command);

    long devnum = 0;
    int op = 0, dlt = -1, yflag_dlt = -1, status = 0;
    char *device = NULL, *RFileName = NULL, ebuf[PCAP_ERRBUF_SIZE] = {0};
    const char *dlt_name = NULL, *yflag_dlt_name = NULL;
    
    pcap_if_t *devlist;
    bpf_u_int32 netmask = 0;

    netdissect_options *ndo = &Gndo;

    memset(ebuf, 0, sizeof(ebuf));

    char * sp = space;
    int len = MSGCOMM_SPACE_SIZE;

    Dflag = 0, Lflag = 0, Iflag = 0, pflag = 0, Qflag = 0;

    tzset();

    if ((capture_check_command_meet_requirement(command)) == ND_ERR)
    {
        capture_usage();
        RInt(ND_OK);
    }

    int argc = 0;
    if (unlikely(!(argc = capture_convert_command_to_argv(command)))) 
    {
        capture_usage();
        RInt(ND_OK);
    }

    char **argv = (char **)msgcomm_G_argv;

    optind = 1;
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
                    TI("%s", optarg);
                    capture_send_errmsg(MSGCOMM_ERR, "-Q in/out/inout;", optarg);
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
                    capture_send_errmsg(MSGCOMM_ERR, "-y invalid data link type %s", yflag_dlt_name);
                    TE("-y invalid data link type %s", yflag_dlt_name);
                    RInt(ND_ERR);
                }
                break;

            default:
                capture_usage();
                RInt(ND_ERR);
        }

    }

    if (Dflag) {
        capture_show_devices_to_display();
        RInt(CP_FAD);
    }

    if (RFileName != NULL)
    {
        pd = pcap_open_offline_with_tstamp_precision(RFileName, tstamp_precision, ebuf);

        if (pd == NULL) {
            TE("%s", ebuf);
            capture_send_errmsg(MSGCOMM_ERR, "%s", ebuf);
            RInt(ND_ERR);
        }

        dlt = pcap_datalink(pd);
        dlt_name = pcap_datalink_val_to_name(dlt);
        memset(space, 0, MSGCOMM_SPACE_SIZE);
        CAPTURE_SHORTEN_CODE(space, sp, len, "reading from file %s", RFileName);
        if (dlt_name == NULL)
        {
            CAPTURE_SHORTEN_CODE(space, sp, len, ", link-type %u", dlt);
        }
        else
        {
            CAPTURE_SHORTEN_CODE(space, sp, len, ", link-type %s (%s)", dlt_name, pcap_datalink_val_to_description(dlt));
        }
        CAPTURE_SHORTEN_CODE(space, sp, len, ", snapshot length %d", pcap_snapshot(pd));

        if (dlt == DLT_LINUX_SLL2) {
            CAPTURE_SHORTEN_CODE(space, sp, len, "Warning: interface names might be incorrect");
        }

    }
    else
    {
        if (device == NULL)
        {
            if (pcap_findalldevs(&devlist, ebuf) == -1) {
                TE("%s", ebuf);
                capture_send_errmsg(MSGCOMM_ERR, "%s", ebuf);
                RInt(ND_ERR);
            }
            if (devlist == NULL) {
                TE("no interfaces available for capture");
                capture_send_errmsg(MSGCOMM_ERR, "no interfaces available for capture");
                RInt(ND_ERR);
            }
            device = strdup(devlist->name);
            pcap_freealldevs(devlist);
        }

        pd = capture_open_interface(device, ndo, ebuf);
        if (pd == NULL)
        {
            devnum = capture_parse_interface_number(device);
            if (devnum == -1)
            {
                TE("%s", ebuf);
                capture_send_errmsg(MSGCOMM_ERR, "%s", ebuf);
                RInt(ND_ERR);
            }

            device = capture_find_interface_by_number(device, devnum);
            pd = capture_open_interface(device, ndo, ebuf);
            if (pd == NULL) {
                TE("%s", ebuf);
                capture_send_errmsg(MSGCOMM_ERR, "%s", ebuf);
                RInt(ND_ERR);
            }

        }
        
        if (Lflag) {
            capture_show_datalinktype(pd, device);
            pcap_close(pd);
            pd = NULL;
            RInt(ND_OK);
        }

        if (yflag_dlt >= 0)
        {
            if (pcap_set_datalink(pd, yflag_dlt) < 0) {
                TE("%s", pcap_geterr(pd));
                capture_send_errmsg(MSGCOMM_ERR, "%s", pcap_geterr(pd));
                pcap_close(pd);
                pd = NULL;
                RInt(ND_ERR);
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
    }

    char * cmdbuf = capture_copy_argv((char**)(&argv[optind]));
    
    if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0) {
        TE("%s", pcap_geterr(pd));
        capture_send_errmsg(MSGCOMM_ERR, "%s", pcap_geterr(pd));
        pcap_close(pd);
        pd = NULL;
        RInt(ND_ERR);
    }

    if (pcap_setfilter(pd, &fcode) < 0) {
        TE("%s", pcap_geterr(pd));
        capture_send_errmsg(MSGCOMM_ERR, "%s", pcap_geterr(pd));
        pcap_close(pd);
        pd = NULL;
        RInt(ND_ERR);
    }
    
    if (RFileName == NULL)
    {
        memset(space, 0, MSGCOMM_SPACE_SIZE);
        CAPTURE_SHORTEN_CODE(space, sp, len, "%s: ", program_name);
        dlt = pcap_datalink(pd);
        dlt_name = pcap_datalink_val_to_name(dlt);
        CAPTURE_SHORTEN_CODE(space, sp, len, "listening on %s", device);
        if (dlt_name == NULL)
        {
            CAPTURE_SHORTEN_CODE(space, sp, len, ", link-type %u", dlt);
        }
        else
        {
            CAPTURE_SHORTEN_CODE(space, sp, len, ", link-type %s (%s)", dlt_name,
                                 pcap_datalink_val_to_description(dlt));
        }
        CAPTURE_SHORTEN_CODE(space, sp, len, ", snapshot length %d bytes", pcap_snapshot(pd));
    }

    if (unlikely(((capture_reply_to_display(MSGCOMM_SUC, space)) == ND_ERR)))
    {
        TE("capture reply to display failed");
        exit(1);
    }

    #if 0
    memset(G_cp_aa_shared_param, 0, sizeof(struct netdissect_options));
    ndo = (struct netdissect_options *) G_cp_aa_shared_param;
    *ndo = Gndo;
    #endif

    msgcomm_transfer_status_change(msgcomm_st_cppc, MSGCOMM_ST_CPPC);

    struct pollfd fds;
    int fd, ret;
    fd = pcap_get_selectable_fd(pd);
    if (fd == -1)
    {
        TE("pcap_get_selectable_fd() failed: Not supported.");
        pcap_close(pd);
        pd = NULL;
        pcap_freecode(&fcode);
        msgcomm_transfer_status_change(msgcomm_st_runflag_c2d, MSGCOMM_ST_C2D_FD_ERR);
        RInt(ND_ERR);
    }
    fds.fd = fd;
    fds.events = POLLIN;

    while (1)
    {

        unsigned int tmp = 0;
        msgcomm_receive_status_value(msgcomm_st_runflag, tmp);

        if (MSGCOMM_ST_EXIT == tmp)
            break;

        if (MSGCOMM_ST_SAVE == tmp)
            break;

        ret = poll(&fds, 1, 1000);

        if (ret >= 0) 
        {
            if (ret) {
                status = pcap_dispatch(pd, -1, capture_copy_packet, NULL);
                if (status == -2)
                {
                    TE("%s: pcap_breakloop() is called, forcing the loop to terminate.", program_name);
                    msgcomm_transfer_status_change(msgcomm_st_runflag_c2d, MSGCOMM_ST_C2D_PCAP_BREAKLOOP_ERR);
                    break;
                }
                if (status == -1)
                {
                    TE("%s: pcap_dispatch: %s\n", program_name, pcap_geterr(pd));
                    msgcomm_transfer_status_change(msgcomm_st_runflag_c2d, MSGCOMM_ST_C2D_PCAP_DISPATCH_ERR);
                    break;
                }
            }
        }
        else
        {
            TE("poll() error; errno: %d; errmsg: %s", errno, strerror(errno));
            msgcomm_transfer_status_change(msgcomm_st_runflag_c2d, MSGCOMM_ST_C2D_POLL_ERR);
            break;
        }
    }

    pcap_close(pd);
    pd = NULL;
    pcap_freecode(&fcode);

    RInt(ND_OK);
}

