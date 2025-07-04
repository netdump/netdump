

#include "ndo.h"
#include "funcattrs.h"

NORETURN void
nd_trunc_longjmp(ndo_t *ndo)
{
    longjmp(ndo->ndo_early_end, ND_TRUNCATED);
#ifdef _AIX
    /*
     * In AIX <setjmp.h> decorates longjmp() with "#pragma leaves", which tells
     * XL C that the function is noreturn, but GCC remains unaware of that and
     * yields a "'noreturn' function does return" warning.
     */
    ND_UNREACHABLE
#endif /* _AIX */
}
