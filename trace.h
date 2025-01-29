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


#define trace_log(fmt, ...)\
	do {\
		nd_tracef("[%s][%s:%d]"fmt"\n", __TIME__, __func__, __LINE__, ##__VA_ARGS__);\
	} while (0);\


#define TRACE_STARTUP()	do {trace_startup();} while (0);
	

#define T	trace_log


/**
 * @brief Trace 'bool' return-values
 */
#define RBool(code)\
    do {\
        T("return } %s", code ? "TRUE" : "FALSE");\
        return code;\
    } while (0);\


/**
 * @brief Trace 'char' return-values
 */
#define RChar(code)\
    do {\
        T("return } %c", code);\
        return (char) code;\
    } while (0);\


/**
 * @brief Trace 'int' return-values
 */
#define RInt(code)\
    do {\
        T("return } %d", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'char*' return-values
 */
#define RCharPtr(code)\
    do {\
        T("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'const char*' return-values
 */
#define RConstCharPtr(code)\
    do {\
        T("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'void*' return-values
 */
#define RVoidPtr(code)\
    do {\
        T("return } %p", code);\
        return code;\
    } while (0);\


/**
 * @brief Trace 'const void*' return-values
 */
#define RConstVoidPtr(code)\
    do {\
        T("return } %p", code);\
        return code;\
    } while (0);\

#else /* !TRACE */

#define TRACE_STARTUP () /* nothing */

#define T	trace_log

#define returnBool(code)		return code
#define returnChar(code)		return ((int8_t) code)
#define returnCode(code)		return code
#define returnPtr(code)			return code
#define returnCPtr(code)		return code
#define returnCVoidPtr(code)	return code
#define returnVoidPtr(code)		return code
#define returnVoid				return


#define trace_log(fmt, ...)\
    do {\
        fprintf(stderr, "[%s][%s:%d]"fmt"\n", __TIME__, __func__, __LINE__, ##__VA_ARGS__);\
    } while (0);\


#endif /* TRACE/!TRACE */

#endif      // __TRACE_H__