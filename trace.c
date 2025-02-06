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
#include <error.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "common.h"
#include "trace.h"


/**
 * @brief 
 *  File stream pointer for global logging
 */
FILE * trace_G_log = NULL;


/**
 * @brief
 *  The current log level
 */
TLevel CURRENT_LOG_LEVEL = allmesg;


#ifdef TRACE

#if 0
void __attribute((noreturn)) log_message(LogLevel level, const char *file, unsigned int line, const char *format, ...)
    __attribute__((format(printf, 4, 5)));

void log_message(LogLevel level, const char *file, unsigned int line, const char *format, ...) {
    if (level >= current_log_level) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str) - 1] = '\0';

        error_at_line(0, 0, file, line, "[%s] [%s] ", time_str, (level == LOG_LEVEL_DEBUG) ? "DEBUG" :
                      (level == LOG_LEVEL_INFO) ? "INFO" :
                      (level == LOG_LEVEL_WARNING) ? "WARNING" : "ERROR");

        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);

        fprintf(stderr, "\n");
    }
}

#define LOG(level, format, ...) \
    log_message(level, __FILE__, __LINE__, format, ##__VA_ARGS__)
#endif

/**
 * @brief 
 *  Start logging and initialize the global file stream
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
        T (erromsg, "%s", strerror(errno));
        return ND_ERR;
    }

    if (access(path, W_OK) != 0) {
        trace_G_log = stderr;
        T (erromsg, "%s", strerror(errno));
        return ND_ERR;
    } 

    if (access(path, R_OK) != 0) {
        trace_G_log = stderr;
        T (erromsg, "%s", strerror(errno));
        return ND_ERR;
    }
        
    int fd = open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        trace_G_log = stderr;
        T (erromsg, "%s", strerror(errno));
        return ND_ERR;
    }

    close(fd);

    if (unlikely((trace_G_log = freopen(name, "wb", stderr)) == NULL)) {
        trace_G_log = stderr;
        T (erromsg, "%s", strerror(errno));
        return ND_ERR;
    }

    setvbuf(trace_G_log, (char *) 0, _IOFBF, (size_t) 0);

    error_one_per_line = 1;

    T (infomsg, "NETDUMP VERSION %04x-%04x", MAJOR_V, SUB_V);
    TI("lCOREID: %d; PID: %d", lcore_id(), getpid());

    return ND_OK;
}


/**
 * @brief 
 *  TRACE log resource destruction
 */
void trace_resource_destruction(void) {

    TC("called { %s", __func__);

    fflush(trace_G_log);

    fclose(trace_G_log);

    return ;
}


#endif
