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

#ifndef __TRACE_H__
#define __TRACE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include "common.h"


/**
 * @brief 
 *  File stream pointer for global logging
 */
extern FILE * trace_G_log;



/**
 * @brief 
 *  Log Level
 */
typedef enum {
    allmesg,
    dbugmsg,
    infomsg,
    warnmsg,
    erromsg,
} TLevel;


/**
 * @brief
 *  The current log level
 */
extern TLevel CURRENT_LOG_LEVEL;


#ifdef TRACE

/**
 * @brief 
 *  Log file format string
 */
#define TRACE_LOG_FILE_FMT		"trace%d.log"


/**
 * @brief 
 *  Start logging and initialize the global file stream
 */
int32_t trace_startup(void);


/**
 * @brief 
 *  TRACE log resource destruction
 */
void trace_resource_destruction(void);


/**
 * @brief 
 *  Start tracing and logging
 */
#define TRACE_STARTUP()\
    do {\
        if (unlikely((trace_startup()) == ND_ERR)) {\
            fprintf(stderr, "Trace Startup failed");\
            exit(1);\
        }\
    } while (0);\


/**
 * @brief 
 *  TRACE log resource destruction
 */
#define TRACE_DESTRUCTION() do{trace_resource_destruction();} while(0);


/**
 * @brief 
 *  Logging
 */
#define trace_log(level, format, ...) \
    do { \
        if (level >= CURRENT_LOG_LEVEL) { \
            error_at_line(0, 0, __FILE__, __LINE__, "[%s] [%s] " format, \
                          __TIME__, #level, ##__VA_ARGS__); \
        } \
    } while (0)
	

/**
 * @brief 
 *  Re-definition of trace_log
 */
#define T	trace_log


/**
 * @brief
 *  Re-definition of trace_log; loging allmsg 
 */
#define TA(fmt, ...)    trace_log(allmesg, fmt, ##__VA_ARGS__)


/**
 * @brief
 *  Re-definition of trace_log; loging dbugmsg
 */
#define TD(fmt, ...)    trace_log(dbugmsg, fmt, ##__VA_ARGS__)


/**
 * @brief
 *  Re-definition of trace_log; loging infomsg
 */
#define TI(fmt, ...)    trace_log(infomsg, fmt, ##__VA_ARGS__)


/**
 * @brief
 *  Re-definition of trace_log; loging warnmsg
 */
#define TW(fmt, ...)    trace_log(warnmsg, fmt, ##__VA_ARGS__)


/**
 * @brief
 *  Re-definition of trace_log; loging erromsg
 */
#define TE(fmt, ...)    trace_log(erromsg, fmt, ##__VA_ARGS__)


#ifdef TOPTRACE


/**
 * @brief   
 *  Re-definition of trace_log
 */
#define TC(fmt, ...)    trace_log(allmesg, fmt, ##__VA_ARGS__);

/**
 * @brief 
 *  Trace 'bool' return-values
 */
#define RBool(code)\
    do {\
        TC("return } %s", code ? "TRUE" : "FALSE");\
        return code;\
    } while (0);\


/**
 * @brief 
 *  Trace 'char' return-values
 */
#define RChar(code)\
    do {\
        TC("return } %c", code);\
        return (char) code;\
    } while (0);\


/**
 * @brief 
 *  Trace 'int' return-values
 */
#define RInt(code)\
    do {\
        TC("return } %d", code);\
        return code;\
    } while (0);\


/**
 * @brief 
 *  Trace 'unsigned int' return-values
 */
#define RUInt(code)\
    do {\
        TC("return } %d", code);\
        return code;\
    } while (0);\


/**
 * @brief
 *  Trace 'unsigned long' return-values
 */
#define RULong(code)\
    do {\
        TC("return } %lu", code);\
        return code;\
    } while (0);


/**
 * @brief
 *  Trace 'long' return-values
 */
#define RLong(code)              \
    do                           \
    {                            \
        TC("return } %ld", code); \
        return code;             \
    } while (0);


/**
 * @brief 
 *  Trace 'char*' return-values
 */
#define RCharPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief 
 *  Trace 'const char*' return-values
 */
#define RConstCharPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief 
 *  Trace 'void*' return-values
 */
#define RVoidPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief 
 *  Trace 'const void*' return-values
 */
#define RConstVoidPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief 
 *  Trace 'void' return-values
 */
#define RVoid()\
	do {\
        TC("return }");\
         return;\
    } while (0);\

#else

/**
 * @brief 
 *  Re-definition of trace_log
 */
#define TC(fmt, ...)            do {} while(0);

#define RBool(code)		        return code
#define RChar(code)		        return ((char) code)
#define RInt(code)		        return code
#define RUInt(code)             return code
#define RLong(code)             return code
#define RULong(code)            return code
#define RCharPtr(code)			return code
#define RConstCharPtr(code)		return code
#define RConstVoidPtr(code)	    return code
#define RVoidPtr(code)		    return code
#define RVoid()				    return


#endif  /* TOPTRACE */

#else /* !TRACE */


/**
 * @brief 
 *  Start tracing and logging
 */
#define TRACE_STARTUP()                 do {} while(0);


/**
 * @brief 
 *  TRACE log resource destruction
 */
#define TRACE_DESTRUCTION()             do {} while(0);

/**
 * @brief
 *  Logging
 */
#define trace_log(level, format, ...)   do {} while(0);

/**
 * @brief
 *  Re-definition of trace_log
 */
#define T trace_log

/**
 * @brief
 *  Re-definition of trace_log; loging allmsg
 */
#define TA(fmt, ...)                    do {} while(0);

/**
 * @brief
 *  Re-definition of trace_log; loging dbugmsg
 */
#define TD(fmt, ...)                    do {} while(0);

/**
 * @brief
 *  Re-definition of trace_log; loging infomsg
 */
#define TI(fmt, ...)                    do {} while(0);

/**
 * @brief
 *  Re-definition of trace_log; loging warnmsg
 */
#define TW(fmt, ...)                    do {} while(0);

/**
 * @brief
 *  Re-definition of trace_log; loging erromsg
 */
#define TE(fmt, ...)                    do {} while(0);


/**
 * @brief   
 *  Re-definition of trace_log
 */
#define TC(fmt, ...)                    do {} while(0);

#define RBool(code)		        return code
#define RChar(code)		        return ((char) code)
#define RInt(code)		        return code
#define RUInt(code)             return code
#define RLong(code)             return code
#define RULong(code)            return code
#define RCharPtr(code)			return code
#define RConstCharPtr(code)		return code
#define RConstVoidPtr(code)	    return code
#define RVoidPtr(code)		    return code
#define RVoid()				    return


#endif /* TRACE/!TRACE */

#endif      // __TRACE_H__