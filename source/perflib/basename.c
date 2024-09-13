/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

/*
 * windows variant of basename(3). works on ASCIIZ only.
 * unlike unix there two variants of path separators on
 * on windows: slash and backslash.
 */
char *basename(char *path)
{
    char *slash, *bslash, *rv;

    if (path == NULL)
        return NULL;

    slash = strrchr(path, '/');
    bslash = strrchr(path, '\\');
    /*
     * We need to 'normalize' slash and bslash, because comparison between NULL
     * and address is considered as undefined behavior (C11 6.5.8 relational
     * operators).  if both are NULL then there is no separator.  If we found
     * found at least one separator then we can assume the missing separator is
     * the leftmost one (equal to path).  Then we can proceed to pointer
     * comparison to see which separator is the last one (the rightmost).
     */
    if (slash == NULL && bslash == NULL)
        return path;
    if (slash == NULL)
        slash = path;
    if (bslash == NULL)
        bslash = path;
    rv = (slash > bslash) ? slash : bslash;

    /* no separator */
    if (rv == NULL)
        return path;

    /* separator followed by filename */
    if (rv[1] != '\0')
        return &rv[1];

   /*
    * trailing separators ('/'  and '\\') are not counted as part of pathname,
    * we must chop them off here.
    */
    while (rv > path && (*rv == '/' || *rv == '\\'))
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

    return rv;
}
