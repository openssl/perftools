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
#include <openssl/bio.h>
#include <openssl/x509.h>
#include "perflib/err.h"
#include "perflib/perflib.h"

#define RUN_TIME 5

static int error = 0;
static X509_STORE *store = NULL;
static X509 *x509 = NULL;

static int threadcount;

size_t *counts;
OSSL_TIME max_time;

static void do_x509storeissuer(size_t num)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509 *issuer = NULL;
    OSSL_TIME time;

    if (ctx == NULL || !X509_STORE_CTX_init(ctx, store, x509, NULL)) {
        warnx("Failed to initialise X509_STORE_CTX");
        error = 1;
        goto err;
    }

    counts[num] = 0;

    do {
        /*
         * We actually expect this to fail. We've not configured any
         * certificates inside our store. We're just testing calling this
         * against an empty store.
         */
        if (X509_STORE_CTX_get1_issuer(&issuer, ctx, x509) != 0) {
            warnx("Unexpected result from X509_STORE_CTX_get1_issuer");
            error = 1;
            X509_free(issuer);
            goto err;
        }
        issuer = NULL;
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

 err:
    X509_STORE_CTX_free(ctx);
}

static void
usage(char * const argv[])
{
    fprintf(stderr,
            "Usage: %s [-t] [-V] certsdir threadcount\n"
            "-t - terse output\n"
            "-V - print version information and exit\n",
            basename(argv[0]));
}

int main(int argc, char *argv[])
{
    int i;
    OSSL_TIME duration;
    size_t total_count = 0;
    double avcalltime;
    int terse = 0;
    char *cert = NULL;
    int ret = EXIT_FAILURE;
    BIO *bio = NULL;
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
            usage(argv);
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL)
        errx(EXIT_FAILURE, "certsdir is missing");

    cert = perflib_mk_file_path(argv[optind], "servercert.pem");
    if (cert == NULL)
        errx(EXIT_FAILURE, "Failed to allocate cert path");

    optind++;

    if (argv[optind] == NULL)
        errx(EXIT_FAILURE, "threadcount is missing");

    threadcount = atoi(argv[optind]);
    if (threadcount < 1)
        errx(EXIT_FAILURE, "threadcount must be > 0");

    store = X509_STORE_new();
    if (store == NULL || !X509_STORE_set_default_paths(store))
        errx(EXIT_FAILURE, "Failed to create X509_STORE");

    bio = BIO_new_file(cert, "rb");
    if (bio == NULL)
        errx(EXIT_FAILURE, "Unable to load certificate\n");

    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL)
        errx(EXIT_FAILURE, "Failed to read certificate");

    BIO_free(bio);
    bio = NULL;

    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    if (counts == NULL)
        errx(EXIT_FAILURE, "Failed to create counts array");

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (!perflib_run_multi_thread_test(do_x509storeissuer, threadcount, &duration))
        errx(EXIT_FAILURE, "Failed to run the test");

    if (error)
        errx(EXIT_FAILURE, "Error during test");

    for (i = 0; i < threadcount; i++)
        total_count += counts[i];

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;

    if (terse)
        printf("%lf\n", avcalltime);
    else
        printf("Average time per X509_STORE_CTX_get1_issuer() call: %lfus\n",
               avcalltime);

    ret = EXIT_SUCCESS;

    X509_STORE_free(store);
    X509_free(x509);
    BIO_free(bio);
    OPENSSL_free(cert);
    OPENSSL_free(counts);
    return ret;
}
