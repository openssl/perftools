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
#endif	/* _WIN32 */
#include <openssl/ssl.h>
#include "perflib/perflib.h"

#define NUM_CALLS_PER_TEST        10000

int err = 0;

typedef enum {
  INIT_LIB_CTX,
  INIT_LIB_AND_SSL_CTX,
} init_ctx;

struct ctx {
    OSSL_LIB_CTX *libctx;
    SSL_CTX *sctx;
    SSL_CTX *cctx;
};

static SSL_CTX *sctx = NULL, *cctx = NULL;
static int share_ctx = 1;
static char *cert = NULL;
static char *privkey = NULL;
static struct ctx **ctx_pool = NULL;


OSSL_TIME *times;

static int threadcount;
size_t num_calls;
static long pool_size = 16;

typedef enum {
    TC_SSL_CTX,
    TC_OSSL_LIB_CTX_PER_THREAD,
    TC_OSSL_LIB_CTX_POOL,
    TC_SSL_CTX_POOL,
} test_case_t;

static void do_handshake(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME start, end;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;

    if (share_ctx == 1) {
        lsctx = sctx;
        lcctx = cctx;
    }

    start = ossl_time_now();

    for (i = 0; i < num_calls / threadcount; i++) {
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
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);

    if (!ret)
        err = 1;
}

static void do_handshake_ossl_lib_ctx_per_thread(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME start, end;
    OSSL_LIB_CTX *libctx = NULL;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;

    start = ossl_time_now();

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "%s:%d: Failed to create ossl lib context\n", __FILE__, __LINE__);
        err = 1;
        return;
    }

    for (i = 0; i < num_calls / threadcount; i++) {
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
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);

    if (!ret)
        err = 1;

    OSSL_LIB_CTX_free(libctx);
}

static void do_handshake_ossl_lib_ctx_pool(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME start, end;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;
    struct ctx *ctx = NULL;

    start = ossl_time_now();

    ctx = ctx_pool[num % pool_size];
    if (share_ctx == 1) {
        if (!perflib_create_ossl_lib_ctx_pair(ctx->libctx,
                                              TLS_server_method(),
                                              TLS_client_method(),
                                              0, 0, &lsctx, &lcctx, cert,
                                              privkey)) {
            fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
            err = 1;
            return;
        }
    }

    for (i = 0; i < num_calls / threadcount; ++i) {
        if (share_ctx == 0) {
            if (!perflib_create_ossl_lib_ctx_pair(ctx->libctx,
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
    }

    if (share_ctx == 1) {
        SSL_CTX_free(lsctx);
        SSL_CTX_free(lcctx);
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);

    if (!ret)
        err = 1;
}

static void do_handshake_ssl_ctx_pool(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME start, end;
    struct ctx *ssl_ctx = NULL;

    start = ossl_time_now();

    ssl_ctx = ctx_pool[num % pool_size];
    for (i = 0; i < num_calls / threadcount; ++i) {
        ret = perflib_create_ssl_objects(ssl_ctx->sctx, ssl_ctx->cctx, &serverssl, &clientssl,
                                         NULL, NULL);
        ret &= perflib_create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE);
        perflib_shutdown_ssl_connection(serverssl, clientssl);
        serverssl = clientssl = NULL;
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);

    if (!ret)
        err = 1;
}

static void free_ctx_pool()
{
    if (ctx_pool == NULL)
        return;
    for (int i = 0; i < pool_size; ++i) {
        if (ctx_pool[i]) {
            OSSL_LIB_CTX_free(ctx_pool[i]->libctx);
            SSL_CTX_free(ctx_pool[i]->sctx);
            SSL_CTX_free(ctx_pool[i]->cctx);
            OPENSSL_free(ctx_pool[i]);
        }
    }
    OPENSSL_free(ctx_pool);
    ctx_pool = NULL;
}

static int init_ctx_pool(init_ctx init_ctx)
{
    ctx_pool = OPENSSL_zalloc(pool_size * sizeof(*ctx_pool));
    if (ctx_pool == NULL) {
        fprintf(stderr, "%s:%d: Failed to allocate ssl ctx pool\n", __FILE__, __LINE__);
        return 0;
    }

    for (int i = 0; i < pool_size; ++i) {
        SSL_CTX *lsctx = NULL, *lcctx = NULL;
        struct ctx *ctx = NULL;
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

        if (libctx == NULL) {
            fprintf(stderr, "%s:%d: Failed to create ossl lib context\n", __FILE__, __LINE__);
            return 0;
        }

        if (init_ctx == INIT_LIB_AND_SSL_CTX) {
            if (!perflib_create_ossl_lib_ctx_pair(libctx,
                                                  TLS_server_method(),
                                                  TLS_client_method(),
                                                  0, 0, &lsctx, &lcctx, cert,
                                                  privkey)) {
                fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
                OSSL_LIB_CTX_free(libctx);
                return 0;
            }
        }

        ctx = OPENSSL_zalloc(sizeof(*ctx));
        if (ctx == NULL) {
            OSSL_LIB_CTX_free(libctx);
            SSL_CTX_free(lsctx);
            SSL_CTX_free(lcctx);
            return 0;
        }

        ctx->libctx = libctx;
        ctx->sctx = lsctx;
        ctx->cctx = lcctx;
        ctx_pool[i] = ctx;
    }

    return 1;
}

static int test_ossl_lib_ctx_pool(size_t threadcount, OSSL_TIME *duration)
{
    int ret = 0;

    ret = init_ctx_pool(INIT_LIB_CTX);
    if (!ret)
        goto err;

    ret = perflib_run_multi_thread_test(do_handshake_ossl_lib_ctx_pool, threadcount, duration);
    if (!ret)
        printf("Failed to run the test\n");

 err:
    free_ctx_pool();

    return ret;
 }

static int test_ssl_ctx_pool(size_t threadcount, OSSL_TIME *duration)
{
    int ret = 0;

    ret = init_ctx_pool(INIT_LIB_AND_SSL_CTX);
    if (!ret)
        goto err;

    ret = perflib_run_multi_thread_test(do_handshake_ssl_ctx_pool, threadcount, duration);
    if (!ret)
        printf("Failed to run the test\n");

 err:
    free_ctx_pool();

    return ret;
}

void usage(const char *progname)
{
    printf("Usage: %s [options] certsdir threadcount\n", progname);
    printf("-t - terse output\n");
    printf("-s - disable context sharing\n");
    printf("-p - use ossl_lib_ctx per thread\n");
    printf("-P - use ossl_lib_ctx pool\n");
    printf("-l - use ssl ctx pool\n");
    printf("-o - set ossl_lib_ctx pool size\n");
}

int main(int argc, char * const argv[])
{
    double persec;
    OSSL_TIME duration, ttime;
    double avcalltime;
    int ret = EXIT_FAILURE;
    int i;
    int terse = 0;
    int opt;
    int p_flag = 0, P_flag = 0, l_flag = 0;
    char *endptr = NULL;
    test_case_t test_case = TC_SSL_CTX;

    while ((opt = getopt(argc, argv, "tspPo:l")) != -1) {
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
            pool_size = strtol(optarg, &endptr, 0);
            if (errno == ERANGE && pool_size == ULONG_MAX) {
                perror("Overflow occurred");
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            }
            if (endptr == optarg || *endptr) {
                fprintf(stderr, "Invalid input: '%s'\n", optarg);
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            }
            if (pool_size < 1) {
                fprintf(stderr, "Pool size must be a > 0\n");
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            }
            break;
        case 'l':
            l_flag = 1;
            test_case = TC_SSL_CTX_POOL;
            break;
        default:
            usage(basename(argv[0]));
            return EXIT_FAILURE;
        }
    }

    if ((p_flag + P_flag + l_flag) > 1) {
        fprintf(stderr, "Error: -p, -P, and -l are mutually exclusive."
              " Choose only one.\n\n");
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
    times = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (times == NULL) {
        printf("Failed to create times array\n");
        goto err;
    }

    num_calls = NUM_CALLS_PER_TEST;
    if (NUM_CALLS_PER_TEST % threadcount > 0) /* round up */
        num_calls += threadcount - NUM_CALLS_PER_TEST % threadcount;

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
    case TC_SSL_CTX_POOL: {
        int ret = test_ssl_ctx_pool(threadcount, &duration);
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

    ttime = times[0];
    for (i = 1; i < threadcount; i++)
        ttime = ossl_time_add(ttime, times[i]);

    avcalltime = ((double)ossl_time2ticks(ttime) / num_calls) / (double)OSSL_TIME_US;
    persec = ((num_calls * OSSL_TIME_SECOND)
             / (double)ossl_time2ticks(duration));

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
    OPENSSL_free(times);
    if (share_ctx == 1) {
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
    }
    return ret;
}
