/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "getopt.h"

const char *optarg = NULL;
int optind = 0;


int getopt(int argc, char * const argv[], const char *optstr)
{
    char	*o;

    optind++;

    if (optind >= argc)
        return -1;

    optarg = argv[optind];
    if (*optarg != '-') {
        /* missing hyphen, then we are done */
        optarg = NULL;
        return -1;
    }
    optarg++;

    o = strchr(optstr, *optarg);
    if (o == NULL) {
        /* unknown option, report error */
        optarg = NULL;
        return '?';
    }

    if (o[1] == ':') {
        /* option has argument */
        optind++;
        if (optind >= argc) {
            /* but argument is missing, report error */
            optarg = NULL;
            return '?';
        }
        optarg = argv[optind];
    } else {
        optarg = NULL;
    }

    return *o;
}
