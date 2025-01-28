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

#define trace_log(fmt, ...)                                                                                                             \
    do {                                                                                                                                \
        printf("[%s][%s:%d]"fmt"\n", __TIME__, __func__, __LINE__, ##__VA_ARGS__);                                                      \
    } while (0);                                                                                                                        \


#ifdef TRACE

#define T_CALLED(fmt) "called {" fmt
#define T_CREATE(fmt) "create :" fmt
#define T_RETURN(fmt) "return }" fmt

#if USE_REENTRANT
#define TPUTS_TRACE(s)	_nc_set_tputs_trace(s);
#else
#define TPUTS_TRACE(s)	_nc_tputs_trace = s;
#endif

#ifdef HAVE_CONSISTENT_GETENV
#define START_TRACE() \
	if ((_nc_tracing & TRACE_MAXIMUM) == 0) { \
	    int t = _nc_getenv_num("NCURSES_TRACE"); \
	    if (t >= 0) \
		curses_trace((unsigned) t); \
	}
#else
#define START_TRACE() /* nothing */
#endif

/*
 * Many of the _tracef() calls use static buffers; lock the trace state before
 * trying to fill them.
 */
#if USE_REENTRANT
#define USE_TRACEF(mask) _nc_use_tracef(mask)
extern NCURSES_EXPORT(int)	_nc_use_tracef (unsigned);
extern NCURSES_EXPORT(void)	_nc_locked_tracef (const char *, ...) GCC_PRINTFLIKE(1,2);
#else
#define USE_TRACEF(mask) (_nc_tracing & (mask))
#define _nc_locked_tracef _tracef
#endif

#define TR(n, a)	if (USE_TRACEF(n)) _nc_locked_tracef a
#define T(a)		TR(TRACE_CALLS, a)
#define TRACE_RETURN(value,type)     return _nc_retrace_##type((type)(value))
#define TRACE_RETURN1(value,dst)     return _nc_retrace_##dst(value)
#define TRACE_RETURN2(value,dst,src) return _nc_retrace_##dst##_##src(value)
#define TRACE_RETURN_SP(value,type)  return _nc_retrace_##type(SP_PARM, value)

typedef void VoidFunc(void);

#define TR_FUNC_LEN		((sizeof(void *) + sizeof(void (*)(void))) * 2 + 4)
#define TR_FUNC_BFR(max)	char tr_func_data[max][TR_FUNC_LEN]
#define TR_FUNC_ARG(num,func)	_nc_fmt_funcptr(&tr_func_data[num][0], (const char *)&(func), sizeof((func)))

#define returnAttr(code)	TRACE_RETURN(code,attr_t)
#define returnBits(code)	TRACE_RETURN(code,unsigned)
#define returnBool(code)	TRACE_RETURN(code,bool)
#define returnCPtr(code)	TRACE_RETURN1(code,cptr)
#define returnCVoidPtr(code)	TRACE_RETURN1(code,cvoid_ptr)
#define returnChar(code)	TRACE_RETURN(code,char)
#define returnChtype(code)	TRACE_RETURN(code,chtype)
#define returnCode(code)	TRACE_RETURN(code,int)
#define returnIntAttr(code)	TRACE_RETURN2(code,int,attr_t)
#define returnMMask(code)	TRACE_RETURN_SP(code,mmask_t)
#define returnPtr(code)		TRACE_RETURN1(code,ptr)
#define returnSP(code)		TRACE_RETURN1(code,sp)
#define returnVoid		{ T((T_RETURN(""))); return; }
#define returnVoidPtr(code)	TRACE_RETURN1(code,void_ptr)
#define returnWin(code)		TRACE_RETURN1(code,win)

#define returnDB(rc)		do { TR(TRACE_DATABASE,(T_RETURN("code %d"), (rc))); return (rc); } while (0)
#define returnPtrDB(rc)		do { TR(TRACE_DATABASE,(T_RETURN("%p"), (rc))); return (rc); } while (0)
#define returnVoidDB		do { TR(TRACE_DATABASE,(T_RETURN(""))); return; } while (0)

extern NCURSES_EXPORT(NCURSES_BOOL)     _nc_retrace_bool (int);
extern NCURSES_EXPORT(NCURSES_CONST void *) _nc_retrace_cvoid_ptr (NCURSES_CONST void *);
extern NCURSES_EXPORT(SCREEN *)         _nc_retrace_sp (SCREEN *);
extern NCURSES_EXPORT(WINDOW *)         _nc_retrace_win (WINDOW *);
extern NCURSES_EXPORT(attr_t)           _nc_retrace_attr_t (attr_t);
extern NCURSES_EXPORT(char *)           _nc_retrace_ptr (char *);
extern NCURSES_EXPORT(char *)           _nc_trace_ttymode(const TTY *tty);
extern NCURSES_EXPORT(char *)           _nc_varargs (const char *, va_list);
extern NCURSES_EXPORT(chtype)           _nc_retrace_chtype (chtype);
extern NCURSES_EXPORT(const char *)     _nc_altcharset_name(attr_t, chtype);
extern NCURSES_EXPORT(const char *)     _nc_retrace_cptr (const char *);
extern NCURSES_EXPORT(char)             _nc_retrace_char (int);
extern NCURSES_EXPORT(int)              _nc_retrace_int (int);
extern NCURSES_EXPORT(int)              _nc_retrace_int_attr_t (attr_t);
extern NCURSES_EXPORT(mmask_t)          _nc_retrace_mmask_t (SCREEN *, mmask_t);
extern NCURSES_EXPORT(unsigned)         _nc_retrace_unsigned (unsigned);
extern NCURSES_EXPORT(void *)           _nc_retrace_void_ptr (void *);
extern NCURSES_EXPORT(void)             _nc_fifo_dump (SCREEN *);

extern NCURSES_EXPORT(char *)           _nc_fmt_funcptr(char *, const char *, size_t);

#if USE_REENTRANT
NCURSES_WRAPPED_VAR(long, _nc_outchars);
NCURSES_WRAPPED_VAR(const char *, _nc_tputs_trace);
#define _nc_outchars       NCURSES_PUBLIC_VAR(_nc_outchars())
#define _nc_tputs_trace    NCURSES_PUBLIC_VAR(_nc_tputs_trace())
extern NCURSES_EXPORT(void)		_nc_set_tputs_trace (const char *);
extern NCURSES_EXPORT(void)		_nc_count_outchars (long);
#else
extern NCURSES_EXPORT_VAR(const char *) _nc_tputs_trace;
extern NCURSES_EXPORT_VAR(long)         _nc_outchars;
#endif

extern NCURSES_EXPORT_VAR(unsigned)     _nc_tracing;

extern NCURSES_EXPORT(char *) _nc_tracebits (void);
extern NCURSES_EXPORT(char *) _tracemouse (const MEVENT *);
extern NCURSES_EXPORT(void) _tracedump (const char *, WINDOW *);

#if USE_WIDEC_SUPPORT
extern NCURSES_EXPORT(const char *) _nc_viswbuf2 (int, const wchar_t *);
extern NCURSES_EXPORT(const char *) _nc_viswbufn (const wchar_t *, int);
#endif

extern NCURSES_EXPORT(const char *) _nc_viscbuf2 (int, const NCURSES_CH_T *, int);
extern NCURSES_EXPORT(const char *) _nc_viscbuf (const NCURSES_CH_T *, int);

#else /* !TRACE */

#define START_TRACE() /* nothing */

#define T(a)
#define TR(n, a)
#define TPUTS_TRACE(s)
#define TR_FUNC_BFR(max)

#define returnAttr(code)	return code
#define returnBits(code)	return code
#define returnBool(code)	return code
#define returnCPtr(code)	return code
#define returnCVoidPtr(code)	return code
#define returnChar(code)	return ((char) code)
#define returnChtype(code)	return code
#define returnCode(code)	return code
#define returnIntAttr(code)	return code
#define returnMMask(code)	return code
#define returnPtr(code)		return code
#define returnSP(code)		return code
#define returnVoid		return
#define returnVoidPtr(code)	return code
#define returnWin(code)		return code

#define returnDB(code)		return code
#define returnPtrDB(rc)		return rc
#define returnVoidDB		return

#endif /* TRACE/!TRACE */

#endif      // __TRACE_H__