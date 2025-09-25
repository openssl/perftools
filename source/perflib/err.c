/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/e_os2.h>

const char *progname;

static ossl_inline void *
get_progname(void)
{
    if (progname != NULL)
        return progname;

#if defined(__GLIBC__)
    if (program_invocation_name && program_invocation_name[0])
        return program_invocation_name;
#endif

    return NULL;
}

void
vwarnx(const char *fmt, va_list ap)
{
    if (get_progname() != NULL)
        fprintf(stderr, "%s: ", get_progname());
    vfprintf(stderr, fmt, ap);
    putc('\n', stderr);
}

void
errx(int status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
    exit(status);
}

void
warnx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}
