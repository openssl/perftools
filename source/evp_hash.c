/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This CLI tool computes hashes using the specified algorithm. Uses the EVP API
 * by default, but this tool can also use the corresponding deprecated API's.
 * Prints out the average time per hash computation.
 */

#include <stdlib.h>
#include <stdio.h>
#ifndef _WIN32
# include <unistd.h>
# include <libgen.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
#endif	/* _WIN32 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "perflib/perflib.h"

#define RUN_TIME 5
#define DATA_SIZE 1500

static int threadcount;
static OSSL_TIME max_time;

size_t *counts = NULL;
int err = 0;

typedef enum {
    SHA1_ALG = 0,
    SHA224_ALG,
    SHA256_ALG,
    SHA384_ALG,
    SHA512_ALG,
} hash_algorithm_type;

static unsigned char data[DATA_SIZE];
static int update_times = 1;
static const EVP_MD *evp_md = NULL;
static int (*hash_func_deprecated)(void);

int hash_sha1_deprecated()
{
    int i;
    SHA_CTX sha_ctx;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!SHA1_Init(&sha_ctx))
        return 0;

    for (i = 0; i < update_times; i++)
        if (!SHA1_Update(&sha_ctx, data, sizeof(data)))
            return 0;

    return SHA1_Final(md, &sha_ctx);
}

int hash_sha224_deprecated()
{
    int i;
    SHA256_CTX sha256_ctx;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!SHA224_Init(&sha256_ctx))
        return 0;

    for (i = 0; i < update_times; i++)
        if (!SHA224_Update(&sha256_ctx, data, sizeof(data)))
            return 0;

    return SHA224_Final(md, &sha256_ctx);
}

int hash_sha256_deprecated()
{
    int i;
    SHA256_CTX sha256_ctx;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!SHA256_Init(&sha256_ctx))
        return 0;

    for (i = 0; i < update_times; i++)
        if (!SHA256_Update(&sha256_ctx, data, sizeof(data)))
            return 0;

    return SHA256_Final(md, &sha256_ctx);
}

int hash_sha384_deprecated()
{
    int i;
    SHA512_CTX sha512_ctx;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!SHA384_Init(&sha512_ctx))
        return 0;

    for (i = 0; i < update_times; i++)
        if (!SHA384_Update(&sha512_ctx, data, sizeof(data)))
            return 0;

    return SHA384_Final(md, &sha512_ctx);
}

int hash_sha512_deprecated()
{
    int i;
    SHA512_CTX sha512_ctx;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!SHA512_Init(&sha512_ctx))
        return 0;

    for (i = 0; i < update_times; i++)
        if (!SHA512_Update(&sha512_ctx, data, sizeof(data)))
            return 0;

    return SHA512_Final(md, &sha512_ctx);
}


int hash_evp(EVP_MD_CTX *mctx, const EVP_MD *evp_md)
{
    int i;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!EVP_DigestInit(mctx, evp_md))
        return 0;

    for (i = 0; i < update_times; i++)
        if (!EVP_DigestUpdate(mctx, data, sizeof(data)))
            return 0;

    return EVP_DigestFinal(mctx, md, NULL);
}

void do_hash_deprecated(size_t num)
{
    OSSL_TIME time;

    do {
        if (!hash_func_deprecated()) {
            err = 1;
            return;
        }

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
}

void do_hash_evp(size_t num)
{
    OSSL_TIME time;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    if (mctx == NULL)
        return;

    do {
        if (!hash_evp(mctx, evp_md)) {
            err = 1;
            goto err;
        }
 
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

err:
    EVP_MD_CTX_free(mctx);
}

void print_help()
{
    printf("Usage: evp_hash [-h] [-x] [-t] [-u update-times] [-a algorithm] thread-count\n");
    printf("-h - print this help output\n");
    printf("-x - use deprecated API instead of EVP API\n");
    printf("-t - terse output\n");
    printf("-u update-times - times to update digest. 1 for one-shot. By default, do one-shot\n");
    printf("-a algorithm - One of: [SHA1, SHA224, SHA256, SHA384, SHA512]. By default, use SHA1\n");
    printf("thread-count - number of threads\n");
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    size_t total_count = 0;
    double av;
    int terse = 0, deprecated_api = 0, hash_algorithm = SHA1_ALG;
    int j, opt, rc = EXIT_FAILURE;

    while ((opt = getopt(argc, argv, "htxu:a:")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 'x':
            deprecated_api = 1;
            break;
        case 'u':
            update_times = atoi(optarg);
            if (update_times <= 0) {
                fprintf(stderr, "update-times must be a positive integer\n");
                goto out;
            }
            break;
        case 'a':
            if (strcmp(optarg, "SHA1") == 0) {
                hash_algorithm = SHA1_ALG;
            } else if (strcmp(optarg, "SHA224") == 0) {
                hash_algorithm = SHA224_ALG;
            } else if (strcmp(optarg, "SHA256") == 0) {
                hash_algorithm = SHA256_ALG;
            } else if (strcmp(optarg, "SHA384") == 0) {
                hash_algorithm = SHA384_ALG;
            } else if (strcmp(optarg, "SHA512") == 0) {
                hash_algorithm = SHA512_ALG;
            } else {
                fprintf(stderr, "algorithm is one of: [SHA1, SHA224, SHA256, SHA384, SHA512]\n");
                print_help();
                goto out;
            }
            break;
        case 'h':
        default:
            print_help();
            goto out;
        }
    }

    if (argc - optind != 1) {
        fprintf(stderr, "Incorrect number of arguments\n");
        print_help();
        goto out;
    }

    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        fprintf(stderr, "thread-count must be a positive integer\n");
        print_help();
        goto out;
    }

    if (!RAND_bytes((unsigned char *)data, sizeof(data)))
        goto out;

    counts = OPENSSL_zalloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        fprintf(stderr, "Failed to create counts array\n");
        goto out;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (deprecated_api) {
        switch (hash_algorithm) {
        case SHA1_ALG:
            hash_func_deprecated = hash_sha1_deprecated;
            break;
        case SHA224_ALG:
            hash_func_deprecated = hash_sha224_deprecated;
            break;
        case SHA256_ALG:
            hash_func_deprecated = hash_sha256_deprecated;
            break;
        case SHA384_ALG:
            hash_func_deprecated = hash_sha384_deprecated;
            break;
        case SHA512_ALG:
            hash_func_deprecated = hash_sha512_deprecated;
            break;
        default:
            err = 1;
            goto out;
        }
        err = !perflib_run_multi_thread_test(do_hash_deprecated, threadcount, &duration) || err;
    } else {
        switch (hash_algorithm) {
        case SHA1_ALG:
            evp_md = EVP_sha1();
            break;
        case SHA224_ALG:
            evp_md = EVP_sha224();
            break;
        case SHA256_ALG:
            evp_md = EVP_sha256();
            break;
        case SHA384_ALG:
            evp_md = EVP_sha384();
            break;
        case SHA512_ALG:
            evp_md = EVP_sha512();
            break;
        default:
            err = 1;
            goto out;
        }

        err = !perflib_run_multi_thread_test(do_hash_evp, threadcount, &duration) || err;
    }

    if (err) {
        fprintf(stderr, "Error during test\n");
        goto out;
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
        printf("Average time per hash: %lfus\n", av);

    rc = EXIT_SUCCESS;
out:
    OPENSSL_free(counts);
    return rc;
}
