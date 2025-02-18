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

#define NUM_CALLS_PER_TEST        1000000

int err = 0;

static SSL_CTX *sctx = NULL, *cctx = NULL;
static int share_ctx = 1;
static char *cert = NULL;
static char *privkey = NULL;
static const SSL_METHOD *smethod, *cmethod;

OSSL_TIME *times;

static int threadcount;
size_t num_calls;
int buf_size = 1024;

static void do_writeread(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CTX *lsctx = NULL, *lcctx = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME start, end;
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
            err = 1;
            return;
        }
    }

    /* Setup connection. */
    ret = perflib_create_ssl_objects(lsctx, lcctx, &serverssl, &clientssl,
                                     NULL, NULL);
    ret &= perflib_create_bare_ssl_connection(serverssl, clientssl,
                                              SSL_ERROR_NONE);
    if (!ret) {
        err = 1;
        return;
    }

    start = ossl_time_now();

    for (i = 0; i < num_calls / threadcount; i++) {
        size_t written = 0;
        if (SSL_write_ex(clientssl, cbuf, buf_size, &written) <= 0) {
            fprintf(stderr, "Failed to write data\n");
            err = 1;
            return;
        }
        size_t readbytes;
        if (SSL_read_ex(serverssl, sbuf, buf_size, &readbytes) <= 0) {
            fprintf(stderr, "Failed to read data\n");
            err = 1;
            return;
        }
        if (readbytes != written) {
            fprintf(stderr, "Failed to read %ld bytes, got %ld\n", written, readbytes);
            err = 1;
            return;
        }
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);

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
    OSSL_TIME duration, ttime;
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
                printf("Buffer size argument must be > 0\n");
                return EXIT_FAILURE;
            }
            break;
        default:
            printf("Usage: %s [-t] [-s] [-d] [-b size] certsdir threadcount\n",
                   basename(argv[0]));
            printf("-t - terse output\n");
            printf("-s - disable context sharing\n");
            printf("-d - use DTLS as connection method\n");
            printf("-b - size of buffer to write and read (Default: 1024)\n");
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        printf("certsdir is missing\n");
        goto err;
    }
    cert = perflib_mk_file_path(argv[optind], "servercert.pem");
    privkey = perflib_mk_file_path(argv[optind], "serverkey.pem");
    if (cert == NULL || privkey == NULL) {
        printf("Failed to allocate cert/privkey\n");
        goto err;
    }
    optind++;

    if (argv[optind] == NULL) {
        printf("threadcount argument missing\n");
        goto err;
    }
    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        printf("threadcount must be > 0\n");
        goto err;
    }
    times = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (times == NULL) {
        printf("Failed to create times array\n");
        goto err;
    }

    num_calls = NUM_CALLS_PER_TEST;
    if (NUM_CALLS_PER_TEST % threadcount > 0) /* round up */
        num_calls += threadcount - NUM_CALLS_PER_TEST % threadcount;

    if (share_ctx == 1) {
        if (!perflib_create_ssl_ctx_pair(smethod, cmethod, 0, 0,
                                         &sctx, &cctx, cert, privkey)) {
            printf("Failed to create SSL_CTX pair\n");
            goto err;
        }
    }

    if (!perflib_run_multi_thread_test(do_writeread, threadcount, &duration)) {
        printf("Failed to run the test\n");
        goto err;
    }

    if (err) {
        printf("Error during test\n");
        goto err;
    }

    ttime = times[0];
    for (i = 1; i < threadcount; i++)
        ttime = ossl_time_add(ttime, times[i]);

    avcalltime = ((double)ossl_time2ticks(ttime) / num_calls) / (double)OSSL_TIME_US;

    if (terse) {
        printf("%lf\n", avcalltime);
    } else {
        printf("Average time per write/read: %lfus\n", avcalltime);
    }

    ret = EXIT_SUCCESS;
 err:
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(times);
    if (share_ctx == 1) {
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
    }
    return ret;
}
