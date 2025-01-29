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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "trace.h"
#include "common.h"

#ifdef TRACE

/**
 * @brief File stream pointer for global logging
 */
FILE * trace_G_log = NULL;


/**
 * @brief Logging
 * @brief fmt Formatting parameters
 */
void nd_tracef(const char *fmt, ...) {

    va_list ap;

    va_start(ap, fmt);

    vfprintf(trace_G_log, fmt, ap);

    va_end(ap);

    return ;
}

/**
 * @brief Trace 'bool' return-values
 */
bool _inside_tracef_bool(uint8_t code)
{
    T("return } %s", code ? "TRUE" : "FALSE");
    return code;
}

/**
 * @brief Trace 'char' return-values
 */
int8_t _inside_tracef_char(int8_t code)
{
    T("return } %c", code);
    return (int8_t) code;
}

/**
 * @brief Trace 'int' return-values
 */
int32_t _inside_tracef_int(int32_t code)
{
    T("return } %d", code);
    return code;
}

/**
 * @brief Trace 'unsigned' return-values
 */
uint32_t _inside_tracef_unsigned(uint32_t code)
{
    T("return } %#x", code);
    return code;
}

/**
 * @brief Trace 'char*' return-values
 */
int8_t * _inside_tracef_ptr(int8_t * code)
{
    T("return } %p", code);
    return code;
}

/**
 * @brief Trace 'const char*' return-values
 */
const int8_t * _inside_tracef_cptr(const int8_t *code)
{
    T("return } %p", code);
    return code;
}

/**
 * @brief Trace 'const void*' return-values
 */
const void * _inside_tracef_cvoid_ptr(const void *code)
{
    T("return } %p", code);
    return code;
}

/**
 * @brief Trace 'void*' return-values
 */
void * _inside_tracef_void_ptr(void *code)
{
    T("return } %p", code);
    return code;
}


/**
 * @brief Start logging and initialize the global file stream
 */
int32_t trace_startup (void) {

    char name[64] = {0};

    snprintf(name, 64, TRACE_LOG_FILE_FMT, lcore_id());

    if ((access(name, F_OK) == 0)) {
        unlink(name);
    }

    char path [256] = {0};
    if ((getcwd(path, 256)) == 0) {
        trace_G_log = stderr;
        T ("errmsg: %s", strerror(errno));
        return ND_ERR;
    }

    if (access(path, W_OK) != 0) {
        trace_G_log = stderr;
        T ("errmsg: %s", strerror(errno));
        return ND_ERR;
    } 

    if (access(path, R_OK) != 0) {
        trace_G_log = stderr;
        T ("errmsg: %s", strerror(errno));
        return ND_ERR;
    }
        
    int fd = open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        trace_G_log = stderr;
        T ("errmsg: %s", strerror(errno));
        return ND_ERR;
    }

    if ((trace_G_log = fdopen(fd, "wb")) == NULL) {
        trace_G_log = stderr;
        T ("errmsg: %s", strerror(errno));
        return ND_ERR;
    }

    setvbuf(trace_G_log, (char *) 0, _IOFBF, (size_t) 0);

    T ("NETDUMP VERSION %04x-%04x", MAJOR_V, SUB_V);

    return ND_OK;
}

#endif
