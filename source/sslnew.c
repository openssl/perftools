/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif	/* _WIN32 */
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include "perflib/perflib.h"

#define RUN_TIME 5

int err = 0;
static SSL_CTX *ctx;

static int threadcount;

size_t *counts;
OSSL_TIME max_time;

void do_sslnew(size_t num)
{
    SSL *s;
    BIO *rbio, *wbio;
    OSSL_TIME time;

    counts[num] = 0;

    do {
        s = SSL_new(ctx);
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());

        if (s == NULL || rbio == NULL || wbio == NULL) {
            err = 1;
            BIO_free(rbio);
            BIO_free(wbio);
        } else {
            /* consumes the rbio/wbio references */
            SSL_set_bio(s, rbio, wbio);
        }

        SSL_free(s);
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    size_t total_count = 0;
    double avcalltime;
    int terse = 0;
    int rc = EXIT_FAILURE;
    int i;
    int opt;

    while ((opt = getopt(argc, argv, "tV")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            printf("Usage: %s [-t] [-V] threadcount\n", basename(argv[0]));
            printf("-t - terse output\n");
            printf("-V - print version information and exit\n");
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        printf("threadcount is missing\n");
        return EXIT_FAILURE;
    }
    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        printf("threadcount must be > 0\n");
        return EXIT_FAILURE;
    }

    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        printf("Failed to create counts array\n");
        return EXIT_FAILURE;
    }

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        printf("Failure to create SSL_CTX\n");
        goto out;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (!perflib_run_multi_thread_test(do_sslnew, threadcount, &duration)) {
        printf("Failed to run the test\n");
        goto out;
    }

    if (err) {
        printf("Error during test\n");
        goto out;
    }

    for (i = 0; i < threadcount; i++)
        total_count += counts[i];

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;

    if (terse)
        printf("%lf\n", avcalltime);
    else
        printf("Average time per SSL/BIO creation call: %lfus\n",
               avcalltime);
    rc = EXIT_SUCCESS;
out:
    SSL_CTX_free(ctx);
    OPENSSL_free(counts);
    return rc;
}
