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

extern FILE * trace_G_log;

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

#define TRACE_RETURN(value,type)     	return _inside_tracef_##type((type)(value))
#define TRACE_RETURN1(value,dst)     	return _nc_retrace_##dst(value)


#define returnBits(code)		TRACE_RETURN(code,unsigned)
#define returnBool(code)		TRACE_RETURN(code,bool)
#define returnChar(code)		TRACE_RETURN(code,char)
#define returnCode(code)		TRACE_RETURN(code,int)
#define returnPtr(code)			TRACE_RETURN(code,ptr)

#define returnCPtr(code)		TRACE_RETURN1(code,cptr)
#define returnCVoidPtr(code)	TRACE_RETURN1(code,cvoid_ptr)
#define returnVoidPtr(code)		TRACE_RETURN1(code,void_ptr)

#define returnVoid			{ T((T_RETURN(""))); return; }


extern bool     			_inside_tracef_bool(uint8_t code);
extern int8_t             	_inside_tracef_char (int8_t);
extern int32_t              _inside_tracef_int (int32_t);
extern uint32_t         	_inside_tracef_unsigned (uint32_t);
extern int8_t *           	_inside_tracef_ptr (int8_t *);
extern const int8_t * 		_inside_tracef_cptr(const int8_t *code);
extern void * 				_inside_tracef_void_ptr(void *code);
extern const void * 		_inside_tracef_cvoid_ptr(const void *code);

#else /* !TRACE */

#define TRACE_STARTUP () /* nothing */

#define T	trace_log

#define returnBits(code)		return code
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