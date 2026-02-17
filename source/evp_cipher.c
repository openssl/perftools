/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This CLI tool encrypts random data using the specified algorithm.
 * Prints out the average time per encryption.
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#ifndef _WIN32
# include <unistd.h>
#else
# include "perflib/getopt.h"
#endif	/* _WIN32 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "perflib/perflib.h"
#include "perflib/basename.h"

#define RUN_TIME 5
#define DATA_SIZE 16

static int threadcount;
static OSSL_TIME max_time;

size_t *counts = NULL;
int err = 0;

typedef enum {
    EVP_ISOLATED = 0,
    EVP_SHARED,
} operation_type;

static unsigned char data[DATA_SIZE];
static int update_times = 1;
static const EVP_CIPHER *evp_cipher = NULL;
static unsigned char *key = NULL;
static unsigned char *iv = NULL;

int cipher_encrypt(EVP_CIPHER_CTX *ctx)
{
    unsigned char ciphertext[256];
    int i, tmp_len, out_len = 0, ret = 0;

    for (i = 0; i < update_times; i++) {
        if (!EVP_CipherUpdate(ctx, ciphertext + out_len, &tmp_len, data, DATA_SIZE))
            goto err;
        out_len += tmp_len;
    }

    if (!EVP_CipherFinal_ex(ctx, ciphertext + out_len, &tmp_len))
        goto err;

    ret = 1;
err:
    return ret;
}

static int cipher_isolated()
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL || !EVP_CipherInit_ex2(ctx, evp_cipher, key, iv, 1, NULL))
        goto err;

    ret = cipher_encrypt(ctx);
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static void do_cipher_isolated(size_t num)
{
    OSSL_TIME time;

    do {
        if (!cipher_isolated()) {
            err = 1;
            return;
        }

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
}

static void do_cipher_shared(size_t num)
{
    OSSL_TIME time;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL || !EVP_CipherInit_ex2(ctx, evp_cipher, key, iv, 1, NULL)) {
        err = 1;
        goto err;
    }

    do {
        if (!cipher_encrypt(ctx)) {
            err = 1;
            goto err;
        }

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

err:
    EVP_CIPHER_CTX_free(ctx);
}

static void print_help(FILE *file)
{
#ifdef HAVE_OSSL_LIB_CTX_FREEZE
    fprintf(file, "Usage: evp_cipher [-h] [-f] [-t] [-o operation] [-u update-times] [-a algorithm] [-V] thread-count\n");
#else
    fprintf(file, "Usage: evp_cipher [-h] [-t] [-o operation] [-u update-times] [-a algorithm] [-V] thread-count\n");
#endif
    fprintf(file, "-h - print this help output\n");
    fprintf(file, "-t - terse output\n");
#ifdef HAVE_OSSL_LIB_CTX_FREEZE
    fprintf(file, "-f - freeze default context\n");
#endif
    fprintf(file, "-o operation - mode of operation. One of [evp_isolated, evp_shared] (default: evp_shared)\n");
    fprintf(file, "-u update-times - times to update (default: 1)\n");
    fprintf(file, "-a algorithm - One of: [AES-128-CBC, AES-256-CBC] (default: AES-128-CBC)\n");
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
    int key_len, iv_len;
    char *getopt_options = "Vhto:u:a:";
#ifdef HAVE_OSSL_LIB_CTX_FREEZE
    int freeze = 0;
    getopt_options = "Vhto:u:a:f";
#endif

    while ((opt = getopt(argc, argv, getopt_options)) != -1) {
	switch (opt) {
#ifdef HAVE_OSSL_LIB_CTX_FREEZE
        case 'f':
            freeze = 1;
            break;
#endif
        case 't':
            terse = 1;
            break;
        case 'o':
            if (strcmp(optarg, "evp_isolated") == 0) {
                operation = EVP_ISOLATED;
            } else if (strcmp(optarg, "evp_shared") == 0) {
                operation = EVP_SHARED;
            } else {
                fprintf(stderr, "operation is one of [evp_isolated, evp_shared]\n");
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
        case 'a':
            if (strcmp(optarg, "AES-128-CBC") == 0) {
                evp_cipher = EVP_aes_128_cbc();
            } else if (strcmp(optarg, "AES-256-CBC") == 0) {
                evp_cipher = EVP_aes_256_cbc();
            } else {
                fprintf(stderr, "algorithm is one of: [AES-128-CBC, AES-256-CBC]\n");
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

    if (evp_cipher == NULL)
        evp_cipher = EVP_aes_128_cbc();

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

    if (!RAND_bytes((unsigned char *)data, sizeof(data)))
        goto err;

    key_len = EVP_CIPHER_get_key_length(evp_cipher);
    iv_len = EVP_CIPHER_get_iv_length(evp_cipher);
    if (iv_len < 0)
        goto err;

    key = OPENSSL_malloc(key_len);
    if (key == NULL || !RAND_bytes(key, key_len))
        goto err;

    if (iv > 0) {
        iv = OPENSSL_malloc(iv_len);
        if (iv == NULL || !RAND_bytes(iv, iv_len))
            goto err;
    }

    counts = OPENSSL_zalloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        fprintf(stderr, "Failed to create counts array\n");
        goto err;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

#ifdef HAVE_OSSL_LIB_CTX_FREEZE
    if (freeze) {
        if (OSSL_LIB_CTX_freeze(NULL, NULL) == 0) {
            fprintf(stderr, "Freezing LIB CTX failed\n");
            goto err;
        }
    }
#endif

    switch (operation) {
    case EVP_ISOLATED:
        err = !perflib_run_multi_thread_test(do_cipher_isolated, threadcount, &duration) || err;
        break;
    case EVP_SHARED:
        err = !perflib_run_multi_thread_test(do_cipher_shared, threadcount, &duration) || err;
        break;
    default:
        goto err;
    }

    if (err) {
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
        printf("Average time per encryption: %lfus\n", av);

    rc = EXIT_SUCCESS;
err:
    OPENSSL_free(counts);
    OPENSSL_free(key);
    OPENSSL_free(iv);
    return rc;
}
