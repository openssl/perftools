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
#include <errno.h>
#ifndef _WIN32
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif /* _WIN32 */
#include <openssl/ssl.h>
#include "perflib/perflib.h"

#define RUN_TIME 5

int err = 0;

static SSL_CTX *sctx = NULL, *cctx = NULL;
static int share_ctx = 1;
static char *cert = NULL;
static char *privkey = NULL;
static OSSL_LIB_CTX **libctx_pool = NULL;


size_t *counts;

static int threadcount;
size_t num_calls;
static long ossl_lib_ctx_pool_size = 16;

typedef enum {
    TC_SSL_CTX,
    TC_OSSL_LIB_CTX_PER_THREAD,
    TC_OSSL_LIB_CTX_POOL,
} test_case_t;
OSSL_TIME max_time;

static void do_handshake(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME time;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;

    if (share_ctx == 1) {
        lsctx = sctx;
        lcctx = cctx;
    }

    counts[num] = 0;

    do {
        if (share_ctx == 0) {
            if (!perflib_create_ssl_ctx_pair(TLS_server_method(),
                                             TLS_client_method(),
                                             0, 0, &lsctx, &lcctx, cert,
                                             privkey)) {
                printf("Failed to create SSL_CTX pair\n");
                break;
            }
        }

        ret = perflib_create_ssl_objects(lsctx, lcctx, &serverssl, &clientssl,
                                         NULL, NULL);
        ret &= perflib_create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE);
        perflib_shutdown_ssl_connection(serverssl, clientssl);
        serverssl = clientssl = NULL;
        if (share_ctx == 0) {
            SSL_CTX_free(lsctx);
            SSL_CTX_free(lcctx);
            lsctx = lcctx = NULL;
        }
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

    if (!ret)
        err = 1;
}

static void do_handshake_ossl_lib_ctx_per_thread(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME time;
    OSSL_LIB_CTX *libctx = NULL;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "%s:%d: Failed to create ossl lib context\n", __FILE__, __LINE__);
        err = 1;
        return;
    }

    counts[num] = 0;

    do {
        if (!perflib_create_ossl_lib_ctx_pair(libctx,
                                              TLS_server_method(),
                                              TLS_client_method(),
                                              0, 0, &lsctx, &lcctx, cert,
                                              privkey)) {
            fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
            err = 1;
            return;
        }


        ret = perflib_create_ssl_objects(lsctx, lcctx, &serverssl, &clientssl,
                                         NULL, NULL);
        ret &= perflib_create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE);
        perflib_shutdown_ssl_connection(serverssl, clientssl);
        serverssl = clientssl = NULL;
        SSL_CTX_free(lsctx);
        SSL_CTX_free(lcctx);
        lsctx = lcctx = NULL;
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

    if (!ret)
        err = 1;

    OSSL_LIB_CTX_free(libctx);
}

static void do_handshake_ossl_lib_ctx_pool(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME time;
    OSSL_LIB_CTX *libctx = NULL;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;

    libctx = libctx_pool[num % ossl_lib_ctx_pool_size];
    if (share_ctx == 1) {
        if (!perflib_create_ossl_lib_ctx_pair(libctx,
                                              TLS_server_method(),
                                              TLS_client_method(),
                                              0, 0, &lsctx, &lcctx, cert,
                                              privkey)) {
            fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
            err = 1;
            return;
        }
    }

    counts[num] = 0;

    do {
        if (share_ctx == 0) {
            if (!perflib_create_ossl_lib_ctx_pair(libctx,
                                                  TLS_server_method(),
                                                  TLS_client_method(),
                                                  0, 0, &lsctx, &lcctx, cert,
                                                  privkey)) {
                fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
                err = 1;
                return;
            }
        }

        ret = perflib_create_ssl_objects(lsctx, lcctx, &serverssl, &clientssl,
                                         NULL, NULL);
        ret &= perflib_create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE);
        perflib_shutdown_ssl_connection(serverssl, clientssl);
        serverssl = clientssl = NULL;
        if (share_ctx == 0) {
            SSL_CTX_free(lsctx);
            SSL_CTX_free(lcctx);
            lsctx = lcctx = NULL;
        }
        counts[num]++;
        time = ossl_time_now();
    }
    while (time.t < max_time.t);

    if (share_ctx == 1) {
        SSL_CTX_free(lsctx);
        SSL_CTX_free(lcctx);
    }

    if (!ret)
        err = 1;
}

static int init_ossl_lib_ctx_pool()
{
    libctx_pool = OPENSSL_malloc(ossl_lib_ctx_pool_size * sizeof(*libctx_pool));
    if (libctx_pool == NULL)
        return 1;

    for (int i = 0; i < ossl_lib_ctx_pool_size; ++i) {
        libctx_pool[i] = OSSL_LIB_CTX_new();
        if (libctx_pool[i] == NULL) {
            fprintf(stderr, "%s:%d: Failed to create ossl lib context\n", __FILE__, __LINE__);
            return 0;
        }
    }

    return 1;
}

static void free_ossl_lib_ctx_pool()
{
    for (int i = 0; i < ossl_lib_ctx_pool_size; ++i) {
        OSSL_LIB_CTX_free(libctx_pool[i]);
    }

    OPENSSL_free(libctx_pool);
}

static int test_ossl_lib_ctx_pool(size_t threadcount, OSSL_TIME *duration)
{
    int ret = 0;

    ret = init_ossl_lib_ctx_pool();
    if (!ret)
        goto err;

    ret = perflib_run_multi_thread_test(do_handshake_ossl_lib_ctx_pool, threadcount, duration);
    if (!ret)
        printf("Failed to run the test\n");

 err:
    free_ossl_lib_ctx_pool();

    return ret;
}

void usage(const char *progname)
{
    printf("Usage: %s [-t] [-s] [-p] [-P] [-o] certsdir threadcount\n", progname);
    printf("-t - terse output\n");
    printf("-s - disable context sharing\n");
    printf("-p - use ossl_lib_ctx per thread\n");
    printf("-P - use ossl_lib_ctx pool\n");
    printf("-o - set ossl_lib_ctx pool size\n");
}

int main(int argc, char * const argv[])
{
    double persec;
    OSSL_TIME duration;
    size_t total_count = 0;
    double avcalltime;
    int ret = EXIT_FAILURE;
    int i;
    int terse = 0;
    int opt;
    int p_flag = 0, P_flag = 0;
    char *endptr = NULL;
    test_case_t test_case = TC_SSL_CTX;

    while ((opt = getopt(argc, argv, "tspPo:")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 's':
            share_ctx = 0;
            break;
        case 'p':
            p_flag = 1;
            test_case = TC_OSSL_LIB_CTX_PER_THREAD;
            break;
        case 'P':
            P_flag = 1;
            test_case = TC_OSSL_LIB_CTX_POOL;
            break;
        case 'o':
            errno = 0;
            ossl_lib_ctx_pool_size = strtol(optarg, &endptr, 0);
            if (errno == ERANGE && ossl_lib_ctx_pool_size == ULONG_MAX) {
                perror("Overflow occurred");
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            }
            if (endptr == optarg || *endptr) {
                fprintf(stderr, "Invalid input: '%s'\n", optarg);
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            }
            if (ossl_lib_ctx_pool_size < 1) {
                fprintf(stderr, "Pool size must be a > 0\n");
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            }
            break;
        default:
            usage(basename(argv[0]));
            return EXIT_FAILURE;
        }
    }

    if ((p_flag + P_flag) > 1) {
        fprintf(stderr,
                "Error: -p and -P mutually exclusive. Choose only one.\n\n");
        usage(basename(argv[0]));
        return EXIT_FAILURE;
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
    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        printf("Failed to create times array\n");
        goto err;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    switch (test_case) {
    case TC_SSL_CTX: {
        if (share_ctx == 1) {
            if (!perflib_create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                                             0, 0, &sctx, &cctx, cert, privkey)) {
                printf("Failed to create SSL_CTX pair\n");
                goto err;
            }
        }

        if (!perflib_run_multi_thread_test(do_handshake, threadcount, &duration)) {
            printf("Failed to run the test\n");
            goto err;
        }
        break;
    }
    case TC_OSSL_LIB_CTX_PER_THREAD: {
         ret =
            perflib_run_multi_thread_test(do_handshake_ossl_lib_ctx_per_thread,
                                          threadcount, &duration);
        if (!ret) {
            printf("Failed to run the test\n");
            goto err;
        }
        break;
    }
    case TC_OSSL_LIB_CTX_POOL: {
        int ret = test_ossl_lib_ctx_pool(threadcount, &duration);
        if (!ret) {
            printf("Failed to run the test\n");
            goto err;
        }
        break;
    }
    default:
        fprintf(stderr, "Invalid test case\n");
        goto err;
    };

    if (err) {
        printf("Error during test\n");
        goto err;
    }

    for (i = 0; i < threadcount; i++)
        total_count += counts[i];

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;
    persec = (double)total_count / RUN_TIME;

    if (terse) {
        printf("%lf\n", avcalltime);
    } else {
        printf("Average time per handshake: %lfus\n", avcalltime);
        printf("Handshakes per second: %lf\n", persec);
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
