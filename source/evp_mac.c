/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This CLI tool computes an HMAC of random data using SHA-256 digest.
 * Prints out the average time per computation.
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdlib.h>
#include <stdio.h>
#ifndef _WIN32
# include <unistd.h>
# include <string.h>
#else
# include "perflib/getopt.h"
#endif	/* _WIN32 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "perflib/perflib.h"
#include "perflib/basename.h"

#define RUN_TIME 5
#define DATA_SIZE 32
#define KEY_SIZE 64

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

static unsigned char data[DATA_SIZE];
static unsigned char key[KEY_SIZE];
static int update_times = 1;

int evp_compute(EVP_MAC_CTX *ctx)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    int i, ret = 0;
    size_t out_len;

    for (i = 0; i < update_times; i++) {
        if (!EVP_MAC_update(ctx, data, DATA_SIZE))
            goto err;
    }

    if (!EVP_MAC_final(ctx, out, &out_len, sizeof(out)))
        goto err;

    ret = 1;
err:
    return ret;
}

static int evp_isolated()
{
    int ret = 0;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (mac == NULL
        || (ctx = EVP_MAC_CTX_new(mac)) == NULL
        || !EVP_MAC_init(ctx, key, KEY_SIZE, params))
        goto err;

    ret = evp_compute(ctx);
err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

static void do_evp_isolated(size_t num)
{
    OSSL_TIME time;

    do {
        if (!evp_isolated()) {
            run_err = 1;
            return;
        }

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
}

static void do_evp_shared(size_t num)
{
    OSSL_TIME time;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if ((mac = EVP_MAC_fetch(NULL, "HMAC", NULL)) == NULL
        || (ctx = EVP_MAC_CTX_new(mac)) == NULL
        || !EVP_MAC_init(ctx, key, KEY_SIZE, params)) {
        run_err = 1;
        goto err;
    }

    do {
        if (!evp_compute(ctx)
            || !EVP_MAC_init(ctx, NULL, 0, NULL)) {
            run_err = 1;
            goto err;
        }

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static int hmac_compute(HMAC_CTX *ctx)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    int i;
    unsigned int out_len;

    for (i = 0; i < update_times; i++) {
        if (!HMAC_Update(ctx, data, DATA_SIZE))
            return 0;
    }

    if (!HMAC_Final(ctx, out, &out_len))
        return 0;

    return 1;
}

static int hmac_isolated()
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    int ret = 0;

    if (ctx == NULL
        || !HMAC_Init_ex(ctx, key, KEY_SIZE, EVP_sha256(), NULL))
        goto err;

    ret = hmac_compute(ctx);
err:
    HMAC_CTX_free(ctx);
    return ret;
}

static void do_deprecated_isolated(size_t num)
{
    OSSL_TIME time;

    do {
        if (!hmac_isolated()) {
            run_err = 1;
            return;
        }

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
}

static void do_deprecated_shared(size_t num)
{
    OSSL_TIME time;
    HMAC_CTX *ctx = HMAC_CTX_new();

    if (ctx == NULL
        || !HMAC_Init_ex(ctx, key, KEY_SIZE, EVP_sha256(), NULL))
        goto err;

    do {
        if (!hmac_compute(ctx)
            || !HMAC_Init_ex(ctx, NULL, 0, NULL, NULL))
            goto err;

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

    return;

err:
    run_err = 1;
    HMAC_CTX_free(ctx);
}

static void print_help(FILE *file)
{
    fprintf(file, "Usage: evp_mac [-h] [-t] [-o operation] [-u update-times] [-V] thread-count\n");
    fprintf(file, "-h - print this help output\n");
    fprintf(file, "-t - terse output\n");
    fprintf(file, "-o operation - mode of operation. One of [evp_isolated, evp_shared, deprecated_isolated, deprecated_shared] (default: evp_shared)\n");
    fprintf(file, "-u update-times - times to update (default: 1)\n");
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

    while ((opt = getopt(argc, argv, "Vhto:u:")) != -1) {
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
        case 'u':
            update_times = atoi(optarg);
            if (update_times <= 0) {
                fprintf(stderr, "update-times must be a positive integer\n");
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

    if (!RAND_bytes((unsigned char *)data, sizeof(data))
        || !RAND_bytes(key, KEY_SIZE))
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
     * Hashing is pretty fast, running in only a few us. But ossl_time2us does
     * integer division and so because the average us computed above is less
     * than the value of OSSL_TIME_US, we wind up with truncation to zero in the
     * math. Instead, manually do the division, casting our values as doubles so
     * that we compute the proper time.
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
