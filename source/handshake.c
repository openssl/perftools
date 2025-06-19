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
#include <openssl/err.h>
#include "perflib/perflib.h"

#define RUN_TIME 5

int err = 0;

typedef enum {
  INIT_LIB_CTX,
  INIT_LIB_AND_SSL_CTX,
} init_ctx;

struct ctxs {
    OSSL_LIB_CTX *libctx;
    SSL_CTX *sctx;
    SSL_CTX *cctx;
};

static SSL_CTX *sctx = NULL, *cctx = NULL;
static int share_ctx = 1;
static char *cert = NULL;
static char *privkey = NULL;
static struct ctxs **ctx_pool = NULL;

size_t *counts;

static int threadcount;
size_t num_calls;
static long pool_size = 16;

typedef enum {
    TC_SSL_CTX,
    TC_OSSL_LIB_CTX_PER_THREAD,
    TC_OSSL_LIB_CTX_POOL,
    TC_SSL_CTX_POOL,
} test_case_t;
OSSL_TIME max_time;
static test_case_t test_case = TC_SSL_CTX;

static void do_handshake(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
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
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
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
            ERR_print_errors_fp(stderr);
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

static void do_handshake_ctx_pool(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    OSSL_TIME time;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;
    struct ctxs *ctx = NULL;

    ctx = ctx_pool[num % pool_size];

    if (test_case == TC_SSL_CTX_POOL) {
        /* Use pre-created SSL_CTX from the pool */
        lsctx = ctx->sctx;
        lcctx = ctx->cctx;
    }

    if (share_ctx == 1 && test_case == TC_OSSL_LIB_CTX_POOL) {
        if (!perflib_create_ossl_lib_ctx_pair(ctx->libctx,
                                              TLS_server_method(),
                                              TLS_client_method(),
                                              0, 0, &lsctx, &lcctx, cert,
                                              privkey)) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
            err = 1;
            return;
        }
    }

    counts[num] = 0;

    do {
        if (share_ctx == 0 && test_case == TC_OSSL_LIB_CTX_POOL) {
            if (!perflib_create_ossl_lib_ctx_pair(ctx->libctx,
                                                  TLS_server_method(),
                                                  TLS_client_method(),
                                                  0, 0, &lsctx, &lcctx, cert,
                                                  privkey)) {
                ERR_print_errors_fp(stderr);
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
        if (share_ctx == 0 && test_case == TC_OSSL_LIB_CTX_POOL) {
            SSL_CTX_free(lsctx);
            SSL_CTX_free(lcctx);
            lsctx = lcctx = NULL;
        }
        counts[num]++;
        time = ossl_time_now();
    }
    while (time.t < max_time.t);

    if (share_ctx == 1 && test_case == TC_OSSL_LIB_CTX_POOL) {
        SSL_CTX_free(lsctx);
        SSL_CTX_free(lcctx);
    }

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
        struct ctxs *ctx = NULL;
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

    if (test_case == TC_SSL_CTX_POOL)
        ret = init_ctx_pool(INIT_LIB_AND_SSL_CTX);
    else
        ret = init_ctx_pool(INIT_LIB_CTX);
    if (!ret)
        goto err;

    ret = perflib_run_multi_thread_test(do_handshake_ctx_pool, threadcount, duration);
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
    printf("-S [n] - use secure memory\n");
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
    int p_flag = 0, P_flag = 0, l_flag = 0;
    char *endptr = NULL;

    while ((opt = getopt(argc, argv, "tspPo:lS:")) != -1) {
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
        case 'S': {
            char *end = NULL;
            errno = 0;
            int sec_mem_size;

            sec_mem_size = (int)strtol(optarg, &end, 10);
            if (errno || end == NULL || *end || sec_mem_size <= 0) {
                fprintf(stderr, "Invalid secure memory size: '%s'\n", optarg);
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            }
            if (CRYPTO_secure_malloc_init(sec_mem_size, 16) == 0) {
                fprintf(stderr, "Secure heap not available\n");
                return EXIT_FAILURE;
            }
            if (CRYPTO_secure_malloc_initialized() == 0) {
                fprintf(stderr, "Secure heap not initialized\n");
                return EXIT_FAILURE;
            }
            break;
        }
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
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
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
        if (!perflib_run_multi_thread_test(do_handshake_ossl_lib_ctx_per_thread,
                                           threadcount, &duration)) {
            printf("Failed to run the test\n");
            goto err;
        }
        break;
    }
    case TC_SSL_CTX_POOL:
    case TC_OSSL_LIB_CTX_POOL: {
        if (!test_ossl_lib_ctx_pool(threadcount, &duration)) {
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
