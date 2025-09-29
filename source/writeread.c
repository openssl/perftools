/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
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
#include "perflib/perflib.h"

#define RUN_TIME 5

int error = 0;

static SSL_CTX *sctx = NULL, *cctx = NULL;
static int share_ctx = 1;
static char *cert = NULL;
static char *privkey = NULL;
static const SSL_METHOD *smethod, *cmethod;

static int threadcount;
int buf_size = 1024;

size_t *counts;
OSSL_TIME max_time;

static void do_writeread(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CTX *lsctx = NULL, *lcctx = NULL;
    int ret = 1;
    OSSL_TIME time;
    char *sbuf, *cbuf;

    /* Prepare client and server buffers. */
    sbuf = OPENSSL_malloc(buf_size);
    cbuf = OPENSSL_malloc(buf_size);
    memset(cbuf, 0xaa, buf_size);

    if (share_ctx == 1) {
        lsctx = sctx;
        lcctx = cctx;
    } else {
        if (!perflib_create_ssl_ctx_pair(smethod, cmethod, 0, 0,
                                         &lsctx, &lcctx, cert, privkey)) {
            fprintf(stderr, "Failed to create SSL_CTX pair\n");
            error = 1;
            return;
        }
    }

    /* Setup connection. */
    ret = perflib_create_ssl_objects(lsctx, lcctx, &serverssl, &clientssl,
                                     NULL, NULL);
    ret &= perflib_create_bare_ssl_connection(serverssl, clientssl,
                                              SSL_ERROR_NONE);
    if (!ret) {
        error = 1;
        return;
    }

    do {
        size_t written = 0;
        if (SSL_write_ex(clientssl, cbuf, buf_size, &written) <= 0) {
            fprintf(stderr, "Failed to write data\n");
            error = 1;
            return;
        }
        size_t readbytes;
        if (SSL_read_ex(serverssl, sbuf, buf_size, &readbytes) <= 0) {
            fprintf(stderr, "Failed to read data\n");
            error = 1;
            return;
        }
        if (readbytes != written) {
            fprintf(stderr, "Failed to read %ld bytes, got %ld\n", written, readbytes);
            error = 1;
            return;
        }
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

    perflib_shutdown_ssl_connection(serverssl, clientssl);
    if (share_ctx == 0) {
        SSL_CTX_free(lsctx);
        SSL_CTX_free(lcctx);
    }
    OPENSSL_free(sbuf);
    OPENSSL_free(cbuf);
}

int main(int argc, char * const argv[])
{
    OSSL_TIME duration;
    size_t total_count = 0;
    double avcalltime;
    int ret = EXIT_FAILURE;
    int i;
    int terse = 0;
    int opt;

    /* Use TLS by default. */
    smethod = TLS_server_method();
    cmethod = TLS_client_method();

    while ((opt = getopt(argc, argv, "tsdb:")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 's':
            share_ctx = 0;
            break;
        case 'd':
            smethod = DTLS_server_method();
            cmethod = DTLS_client_method();
            break;
        case 'b':
            buf_size = atoi(optarg);
            if (buf_size < 1) {
                fprintf(stderr, "Buffer size argument must be > 0\n");
                return EXIT_FAILURE;
            }
            break;
        default:
            fprintf(stderr, "Usage: %s [-t] [-s] [-d] [-b size] certsdir threadcount\n",
                    basename(argv[0]));
            fprintf(stderr, "-t - terse output\n");
            fprintf(stderr, "-s - disable context sharing\n");
            fprintf(stderr, "-d - use DTLS as connection method\n");
            fprintf(stderr, "-b - size of buffer to write and read (Default: 1024)\n");
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        fprintf(stderr, "certsdir is missing\n");
        goto err;
    }
    cert = perflib_mk_file_path(argv[optind], "servercert.pem");
    privkey = perflib_mk_file_path(argv[optind], "serverkey.pem");
    if (cert == NULL || privkey == NULL) {
        fprintf(stderr, "Failed to allocate cert/privkey\n");
        goto err;
    }
    optind++;

    if (argv[optind] == NULL) {
        fprintf(stderr, "threadcount argument missing\n");
        goto err;
    }
    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        fprintf(stderr, "threadcount must be > 0\n");
        goto err;
    }

    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        fprintf(stderr, "Failed to create counts array\n");
        goto err;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (share_ctx == 1) {
        if (!perflib_create_ssl_ctx_pair(smethod, cmethod, 0, 0,
                                         &sctx, &cctx, cert, privkey)) {
            fprintf(stderr, "Failed to create SSL_CTX pair\n");
            goto err;
        }
    }

    if (!perflib_run_multi_thread_test(do_writeread, threadcount, &duration)) {
        fprintf(stderr, "Failed to run the test\n");
        goto err;
    }

    if (error) {
        fprintf(stderr, "Error during test\n");
        goto err;
    }

    for (i = 0; i < threadcount; i++)
        total_count += counts[i];

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;

    if (terse) {
        printf("%lf\n", avcalltime);
    } else {
        printf("Average time per write/read: %lfus\n", avcalltime);
    }

    ret = EXIT_SUCCESS;
 err:
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(counts);
    if (share_ctx == 1) {
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
    }
    return ret;
}
