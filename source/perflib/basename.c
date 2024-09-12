/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/crypto.h>

/*
 * windows variant of basename(3). works on ASCIIZ only.
 * unlike unix there two variants of path separators on
 * on windows: slash and backslash.
 */
const char *basename(char *path)
{
    char *slash, *bslash, *rv;

    if (path == NULL || *path == '\0')
        return ".";

    slash = strrchr(path, '/');
    bslash = strrchr(path, '\\');
    rv = (const char *)((slash > bslash) ? slash : bslash);

    /* no separator */
    if (rv == NULL)
        return (const char *)path;

    /* separator followed by filename */
    if (rv[1] != '\0')
        return (const char *)&rv[1];

   /*
    * trailing separators ('/'  and '\\') are not counted as part of pathname,
    * we must chop them off here.
    */
    while (rv > path && *rv == '/' && *rv == '\\')
        rv--;
    rv[1] = '\0';

    /*
     * search for preceding separator
     */
    while (rv > path && *rv != '/' && *rv != '\\')
        rv--;

    /*
     * move to filename path component if there is any, return the separator
     * otherwise
     */
    if ((*rv == '/' || *rv == '\\') && (rv[1] != '\0'))
        rv++;

    return (const char *)rv;
}
