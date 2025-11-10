/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PERFLIB_NORETURN_H
# define OSSL_PERFLIB_BASENAME_H
# pragma once

# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L \
    && !defined(__cplusplus)
/* _Noreturn is deprecated in C23 in favor to [[noreturn]] */
#  define ossl_noreturn [[noreturn]]
# elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
    && !defined(__cplusplus)
#  define ossl_noreturn _Noreturn
# elif defined(__GNUC__) && __GNUC__ >= 2
#  define ossl_noreturn __attribute__((noreturn))
# elif defined(_MSC_VER)
#  define ossl_noreturn __declspec(noreturn)
# else
#  define ossl_noreturn
# endif


#endif /* OSSL_PERFLIB_NORETURN_H */
