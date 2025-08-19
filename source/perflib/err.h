/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PERFLIB_ERR_H
# define OSSL_PERFLIB_ERR_H
# pragma once

#include <stdarg.h>

extern const char *progname;

extern void vwarnx(const char *, va_list);
extern void errx(int, const char *, ...);
extern void warnx(const char *, ...);

#endif

