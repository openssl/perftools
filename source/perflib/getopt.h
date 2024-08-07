/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PERFLIB_GETOPT_H
# define OSSL_PERFLIB_GETOPT_H
# pragma once

extern const char *optarg;
extern int optind;
extern int getopt(int argc, char * const argv[], const char *);

#endif
