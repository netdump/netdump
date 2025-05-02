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

#ifndef __HEADER_H__
#define __HEADER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include "pcap.h"
#include "trace.h"
#include "ndo.h"
#include "infonode.h"

typedef unsigned char u_char;
typedef unsigned int u_int;

/*
 * Check whether this is GCC major.minor or a later release, or some
 * compiler that claims to be "just like GCC" of that version or a
 * later release.
 */

#if !defined(__GNUC__)
/* Not GCC and not "just like GCC" */
#define ND_IS_AT_LEAST_GNUC_VERSION(major, minor) 0
#else
/* GCC or "just like GCC" */
#define ND_IS_AT_LEAST_GNUC_VERSION(major, minor) \
    (__GNUC__ > (major) ||                        \
     (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#endif

#if __has_attribute(unused) || ND_IS_AT_LEAST_GNUC_VERSION(2, 0)
/*
 * Compiler with support for __attribute__((unused)), or GCC 2.0 and
 * later, so it supports __attribute__((unused)).
 */
#define _U_ __attribute__((unused))
#else
/*
 * We don't know of any way to mark a variable as unused.
 */
#define _U_
#endif

#endif  // __HEADER_H__