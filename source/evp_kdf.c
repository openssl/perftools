/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This CLI tool derives keys from random data with SHA-256 digest.
 * Runs for 5 seconds and prints the average execution time per computation.
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdlib.h>
#include <stdio.h>
#ifndef _WIN32
# include <unistd.h>
#else
# include "perflib/getopt.h"
#endif	/* _WIN32 */

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include "perflib/perflib.h"
#include "perflib/basename.h"

#define RUN_TIME 5
#define KEY_SIZE 256

static int threadcount;
static OSSL_TIME max_time;

size_t *counts = NULL;
int run_err = 0;

typedef enum {
    EVP_SHARED = 0,
    EVP_ISOLATED,
    DEPRECATED_SHARED,
    DEPRECATED_ISOLATED,
} operation_type;

static unsigned char pass[32];
static unsigned char salt[32];
static unsigned int iterations = 2048;

static int evp_isolated()
{
    int ret = 0;
    unsigned char key[KEY_SIZE];
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, pass, sizeof(pass)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt)),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (kdf == NULL
        || (ctx = EVP_KDF_CTX_new(kdf)) == NULL
        || !EVP_KDF_derive(ctx, key, sizeof(key), params))
        goto err;

    ret = 1;
err:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ret;
}

static void do_evp_isolated(size_t num)
{
    OSSL_TIME time;
    size_t count = 0;

    do {
        if (!evp_isolated()) {
            run_err = 1;
            return;
        }

        count++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

    counts[num] = count;
}

static void do_evp_shared(size_t num)
{
    OSSL_TIME time;
    size_t count = 0;
    unsigned char key[KEY_SIZE];
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, pass, sizeof(pass)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt)),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (kdf == NULL || (ctx = EVP_KDF_CTX_new(kdf)) == NULL)
        goto err;

    do {
        if (!EVP_KDF_derive(ctx, key, sizeof(key), params)) {
            run_err = 1;
            goto err;
        }
        EVP_KDF_CTX_reset(ctx);

        count++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
    counts[num] = count;

err:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
}

static void do_deprecated_isolated(size_t num)
{
    OSSL_TIME time;
    size_t count = 0;
    unsigned char key[KEY_SIZE];

    do {
        if (!PKCS5_PBKDF2_HMAC((const char *)pass, sizeof(pass), salt,
            sizeof(salt), iterations, EVP_sha256(), sizeof(key), key)) {
            run_err = 1;
            return;
        }

        count++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
    counts[num] = count;
}

static void do_deprecated_shared(size_t num)
{
    OSSL_TIME time;
    size_t count = 0;
    unsigned char key[KEY_SIZE];
    const EVP_MD *md = EVP_sha256();

    do {
        if (!PKCS5_PBKDF2_HMAC((const char *)pass, sizeof(pass), salt,
            sizeof(salt), iterations, md, sizeof(key), key)) {
            run_err = 1;
            return;
        }

        count++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
    counts[num] = count;
}

static void print_help(FILE *file)
{
    fprintf(file, "Usage: evp_kdf [-h] [-t] [-o operation] [-V] thread-count\n");
    fprintf(file, "-h - print this help output\n");
    fprintf(file, "-t - terse output\n");
    fprintf(file, "-o operation - mode of operation. One of [evp_isolated, evp_shared, deprecated_isolated, deprecated_shared] (default: evp_shared)\n");
    fprintf(file, "-V - print version information and exit\n");
    fprintf(file, "thread-count - number of threads\n");
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    size_t total_count = 0;
    double av;
    int terse = 0, operation = EVP_SHARED;
    int j, opt, rc = EXIT_FAILURE;

    while ((opt = getopt(argc, argv, "Vhto:")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 'o':
            if (strcmp(optarg, "evp_isolated") == 0) {
                operation = EVP_ISOLATED;
            } else if (strcmp(optarg, "evp_shared") == 0) {
                operation = EVP_SHARED;
            } else if (strcmp(optarg, "deprecated_isolated") == 0) {
                operation = DEPRECATED_ISOLATED;
            } else if (strcmp(optarg, "deprecated_shared") == 0) {
                operation = DEPRECATED_SHARED;
            } else {
                fprintf(stderr, "Invalid operation");
                print_help(stderr);
                goto err;
            }
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        case 'h':
            print_help(stdout);
            return EXIT_SUCCESS;
        default:
            print_help(stderr);
            goto err;
        }
    }

    if (argc - optind != 1) {
        fprintf(stderr, "Incorrect number of arguments\n");
        print_help(stderr);
        goto err;
    }

    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        fprintf(stderr, "thread-count must be a positive integer\n");
        print_help(stderr);
        goto err;
    }

    if (!RAND_bytes((unsigned char *)pass, sizeof(pass))
        || !RAND_bytes((unsigned char *)salt, sizeof(salt)))
        goto err;

    counts = OPENSSL_zalloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        fprintf(stderr, "Failed to create counts array\n");
        goto err;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    switch (operation) {
    case EVP_SHARED:
        run_err = !perflib_run_multi_thread_test(do_evp_shared, threadcount, &duration) || run_err;
        break;
    case EVP_ISOLATED:
        run_err = !perflib_run_multi_thread_test(do_evp_isolated, threadcount, &duration) || run_err;
        break;
    case DEPRECATED_SHARED:
        run_err = !perflib_run_multi_thread_test(do_deprecated_shared, threadcount, &duration) || run_err;
        break;
    case DEPRECATED_ISOLATED:
        run_err = !perflib_run_multi_thread_test(do_deprecated_isolated, threadcount, &duration) || run_err;
        break;
    default:
        goto err;
    }

    if (run_err) {
        fprintf(stderr, "Error during test\n");
        goto err;
    }

    for (j = 0; j < threadcount; j++)
        total_count += counts[j];

    /*
     * Computation is pretty fast, running in only a few us. But ossl_time2us
     * does integer division and so because the average us computed above is
     * less than the value of OSSL_TIME_US, we wind up with truncation to zero
     * in the math. Instead, manually do the division, casting our values as
     * doubles so that we compute the proper time.
     */
    av = (double)RUN_TIME * 1e6 * threadcount / total_count;

    if (terse)
        printf("%lf\n", av);
    else
        printf("Average time per computation: %lfus\n", av);

    rc = EXIT_SUCCESS;
err:
    OPENSSL_free(counts);
    return rc;
}
