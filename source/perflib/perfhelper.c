/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "perflib/perflib.h"

char *perflib_mk_file_path(const char *dir, const char *file)
{
    const char *sep = "/";
    size_t dirlen = dir != NULL ? strlen(dir) : 0;
    size_t len = dirlen + strlen(sep) + strlen(file) + 1;
    char *full_file = calloc(1, len);

    if (full_file != NULL) {
        if (dir != NULL && dirlen > 0) {
#ifdef WITH_OPENSSL_FORK
            strlcpy(full_file, dir, len);
            strlcat(full_file, sep, len);
#else
            OPENSSL_strlcpy(full_file, dir, len);
            OPENSSL_strlcat(full_file, sep, len);
#endif
        }
#ifdef WITH_OPENSSL_FORK
        strlcat(full_file, file, len);
#else
        OPENSSL_strlcat(full_file, file, len);
#endif
    }

    return full_file;
}

void perflib_print_version(const char * const progname)
{
    fprintf(stderr,
            "%s version information:\n"
            "  OpenSSL library: %s (%s)\n",
            progname,
            OpenSSL_version(OPENSSL_VERSION),
            OpenSSL_version(OPENSSL_BUILT_ON));
}
