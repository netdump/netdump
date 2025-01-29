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
#include "common.h"


// "called {"

#ifdef TRACE

/**
 * @brief Log file format string
 */
#define TRACE_LOG_FILE_FMT		"tracelog_%d.log"


/**
 * @brief Logging
 * @brief fmt Formatting parameters
 */
void nd_tracef(const char *fmt, ...);

/**
 * @brief Start logging and initialize the global file stream
 */
int32_t trace_startup(void);


/**
 * @brief Logging
 */
#define trace_log(fmt, ...)\
	do {\
		nd_tracef("[%s][%s:%d]"fmt"\n", __TIME__, __func__, __LINE__, ##__VA_ARGS__);\
	} while (0);\


/**
 * Start tracing and logging
 */
#define TRACE_STARTUP()	do {trace_startup();} while (0);
	

/**
 * @brief Re-definition of trace_log
 */
#define T	trace_log


#ifdef TOPTRACE


/**
 * @brief Re-definition of trace_log
 */
#define TC trace_log

/**
 * @brief Trace 'bool' return-values
 */
#define RBool(code)\
    do {\
        TC("return } %s", code ? "TRUE" : "FALSE");\
        return code;\
    } while (0);\


/**
 * @brief Trace 'char' return-values
 */
#define RChar(code)\
    do {\
        TC("return } %c", code);\
        return (char) code;\
    } while (0);\


/**
 * @brief Trace 'int' return-values
 */
#define RInt(code)\
    do {\
        TC("return } %d", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'char*' return-values
 */
#define RCharPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'const char*' return-values
 */
#define RConstCharPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'void*' return-values
 */
#define RVoidPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'const void*' return-values
 */
#define RConstVoidPtr(code)\
    do {\
        TC("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'void' return-values
 */
#define RVoid()\
	do {\
        TC("return }");\
         return;\
    } while (0);\

#endif  /* TOPTRACE */

#else /* !TRACE */


/**
 * Start tracing and logging
 */
#define TRACE_STARTUP () /* nothing */


/**
 * @brief Re-definition of trace_log
 */
#define T	trace_log

/**
 * @brief Re-definition of trace_log
 */
#define TC /* nothing */

#define RBool(code)		        return code
#define RChar(code)		        return ((char) code)
#define RInt(code)		        return code
#define RCharPtr(code)			return code
#define RConstCharPtr(code)		return code
#define RConstVoidPtr(code)	    return code
#define RVoidPtr(code)		    return code
#define RVoid				    return


/**
 * @brief Logging
 */
#define trace_log(fmt, ...)\
    do {\
        fprintf(stderr, "[%s][%s:%d]"fmt"\n", __TIME__, __func__, __LINE__, ##__VA_ARGS__);\
    } while (0);\


#endif /* TRACE/!TRACE */

#endif      // __TRACE_H__