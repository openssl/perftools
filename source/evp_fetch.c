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
# include <unistd.h>
# include <libgen.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif	/* _WIN32 */
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include "perflib/perflib.h"

/*
 * Enable program flag only when version is 3.5 or later
 */
#if OPENSSL_VERSION_MAJOR > 3 || \
    (OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR >= 5)
# define OPENSSL_DO_PQ
# define PQ_GETOPT "q"
# define PQ_USAGE_OPT " [-q]"
# define PQ_USAGE_DESC "-q - include post-quantum algorithms\n"
#else
# define PQ_GETOPT ""
# define PQ_USAGE_OPT ""
# define PQ_USAGE_DESC ""
#endif

#define RUN_TIME 5

/*
 * Update the constant numbers below if you add or remove
 * post-quantum algorithms from the fetch list.
 */
#if defined(OPENSSL_DO_PQ) && !defined(OPENSSL_NO_ML_KEM)
#define FETCH_ENTRY_ML_KEM_N       3
#else
#define FETCH_ENTRY_ML_KEM_N       0
#endif

#if defined(OPENSSL_DO_PQ) && !defined(OPENSSL_NO_ML_DSA)
#define FETCH_ENTRY_ML_DSA_N       3
#else
#define FETCH_ENTRY_ML_DSA_N       0
#endif

#if defined(OPENSSL_DO_PQ) && !defined(OPENSSL_NO_SLH_DSA)
#define FETCH_ENTRY_SLH_DSA_N      6
#else
#define FETCH_ENTRY_SLH_DSA_N      0
#endif

#define FETCH_ENTRY_PQ_ALGS_N      \
    (FETCH_ENTRY_ML_KEM_N + FETCH_ENTRY_ML_DSA_N + FETCH_ENTRY_SLH_DSA_N)

size_t *counts;
OSSL_TIME max_time;

int err = 0;
int pq = 0;

static int threadcount;
size_t num_calls;

static OSSL_LIB_CTX *ctx = NULL;

#define ARRAY_SIZE(a)                               \
  ((sizeof(a) / sizeof(*(a))))

typedef enum {
    FETCH_MD = 0,
    FETCH_CIPHER,
    FETCH_KDF,
    FETCH_MAC,
    FETCH_RAND,
    FETCH_PQ_KEM,
    FETCH_PQ_SIGNATURE,
    FETCH_END
} fetch_type_t;

static const char *type_map[] = {
    [FETCH_MD]           = "MD",
    [FETCH_CIPHER]       = "CIPHER",
    [FETCH_KDF]          = "KDF",
    [FETCH_MAC]          = "MAC",
    [FETCH_RAND]         = "RAND",
    [FETCH_PQ_KEM]       = "KEM",
    [FETCH_PQ_SIGNATURE] = "SIGNATURE",
};

fetch_type_t exclusive_fetch_type = FETCH_END;
char *exclusive_fetch_alg = NULL;

struct fetch_data_entry {
    fetch_type_t ftype;
    const char *alg;
    const char *propq;
};

/*
 * The post quantum algorithms must be the last entries in the
 * list, so we can easily skip them if we don't want them.
 */
static struct fetch_data_entry fetch_entries[] = {
    {FETCH_MD, OSSL_DIGEST_NAME_SHA2_224, NULL},
    {FETCH_MD, OSSL_DIGEST_NAME_SHA2_256, NULL},
    {FETCH_MD, OSSL_DIGEST_NAME_SHA3_224, NULL},
    {FETCH_MD, OSSL_DIGEST_NAME_SHA3_256, NULL},
    {FETCH_CIPHER, "AES-128-GCM", NULL},
    {FETCH_CIPHER, "AES-128-CBC", NULL},
    {FETCH_CIPHER, "AES-256-GCM", NULL},
    {FETCH_CIPHER, "AES-256-CBC", NULL},
    {FETCH_KDF, OSSL_KDF_NAME_HKDF, NULL},
#ifndef OPENSSL_NO_SCRYPT
    {FETCH_KDF, OSSL_KDF_NAME_SCRYPT, NULL},
#endif
    {FETCH_KDF, OSSL_KDF_NAME_KRB5KDF, NULL},
    {FETCH_KDF, OSSL_KDF_NAME_KBKDF, NULL},
#ifndef OPENSSL_NO_BLAKE2
    {FETCH_MAC, OSSL_MAC_NAME_BLAKE2BMAC, NULL},
#endif
#ifndef OPENSSL_NO_CMAC
    {FETCH_MAC, OSSL_MAC_NAME_CMAC, NULL},
#endif
    {FETCH_MAC, OSSL_MAC_NAME_GMAC, NULL},
    {FETCH_MAC, OSSL_MAC_NAME_HMAC, NULL},
#ifndef OPENSSL_NO_POLY1305
    {FETCH_MAC, OSSL_MAC_NAME_POLY1305, NULL},
#endif
#if defined(OPENSSL_DO_PQ) && !defined(OPENSSL_NO_ML_KEM)
    {FETCH_PQ_KEM, "ML-KEM-512", NULL},
    {FETCH_PQ_KEM, "ML-KEM-768", NULL},
    {FETCH_PQ_KEM, "ML-KEM-1024", NULL},
#endif
#if defined(OPENSSL_DO_PQ) && !defined(OPENSSL_NO_ML_DSA)
    {FETCH_PQ_SIGNATURE, "ML-DSA-44", NULL},
    {FETCH_PQ_SIGNATURE, "ML-DSA-65", NULL},
    {FETCH_PQ_SIGNATURE, "ML-DSA-87", NULL},
#endif
#if defined(OPENSSL_DO_PQ) && !defined(OPENSSL_NO_SLH_DSA)
    {FETCH_PQ_SIGNATURE, "SLH-DSA-SHA2-128s", NULL},
    {FETCH_PQ_SIGNATURE, "SLH-DSA-SHA2-192s", NULL},
    {FETCH_PQ_SIGNATURE, "SLH-DSA-SHA2-256s", NULL},
    {FETCH_PQ_SIGNATURE, "SLH-DSA-SHA2-128f", NULL},
    {FETCH_PQ_SIGNATURE, "SLH-DSA-SHA2-192f", NULL},
    {FETCH_PQ_SIGNATURE, "SLH-DSA-SHA2-256f", NULL},
#endif
};

void do_fetch(size_t num)
{
    OSSL_TIME time;
    size_t i, j;
    const char *fetch_alg = NULL;
    int array_size = ARRAY_SIZE(fetch_entries);

    /*
     * Using smaller modulo to shrink the array
     * and exclude the last FETCH_ENTRY_PQ_ALGS_N entries.
     */
    if (!pq) {
        array_size -= FETCH_ENTRY_PQ_ALGS_N;
    }

    counts[num] = 0;

    /*
     * Going through the fetch entries num_calls / threadcount times.
     *
     * Mind a little deviation as the (num_calls / threadcount) does not have
     * to be a multiple of the number of fetch entries therefore at the last
     * iteration we may not check all the algorithms.
     */
    do {
        /*
         * If we set a fetch type, always use that
         */
        if (exclusive_fetch_type == FETCH_END) {
            j = i % array_size;
            fetch_alg = fetch_entries[j].alg;
            j = fetch_entries[j].ftype;
        } else {
            j = exclusive_fetch_type;
            fetch_alg = exclusive_fetch_alg;
        }

        if (err == 1)
            return;

        switch (j) {
        case FETCH_MD: {
            EVP_MD *md = EVP_MD_fetch(ctx, fetch_alg,
                                      fetch_entries[j].propq);
            if (md == NULL) {
                fprintf(stderr, "Failed to fetch %s\n", fetch_alg);
                err = 1;
                return;
            }
            EVP_MD_free(md);
            break;
        }
        case FETCH_CIPHER: {
            EVP_CIPHER *cph = EVP_CIPHER_fetch(ctx, fetch_alg,
                                               fetch_entries[j].propq);
            if (cph == NULL) {
                fprintf(stderr, "Failed to fetch %s\n", fetch_alg);
                err = 1;
                return;
            }
            EVP_CIPHER_free(cph);
            break;
        }
        case FETCH_KDF: {
            EVP_KDF *kdf = EVP_KDF_fetch(ctx, fetch_alg,
                                         fetch_entries[j].propq);
            if (kdf == NULL) {
                fprintf(stderr, "Failed to fetch %s\n", fetch_alg);
                err = 1;
                return;
            }
            EVP_KDF_free(kdf);
            break;
        }
        case FETCH_MAC: {
            EVP_MAC *mac = EVP_MAC_fetch(ctx, fetch_alg,
                                         fetch_entries[j].propq);
            if (mac == NULL) {
                fprintf(stderr, "Failed to fetch %s\n", fetch_alg);
                err = 1;
                return;
            }
            EVP_MAC_free(mac);
            break;
        }
        case FETCH_RAND: {
            EVP_RAND *rnd = EVP_RAND_fetch(ctx, fetch_alg,
                                           fetch_entries[j].propq);
            if (rnd == NULL) {
                fprintf(stderr, "Failed to fetch %s\n", fetch_alg);
                err = 1;
                return;
            }
            EVP_RAND_free(rnd);
            break;
        }
        case FETCH_PQ_KEM: {
            EVP_KEM *kem = EVP_KEM_fetch(ctx, fetch_alg,
                                         fetch_entries[j].propq);
            if (kem == NULL) {
                fprintf(stderr, "Failed to fetch %s\n", fetch_alg);
                err = 1;
                return;
            }
            EVP_KEM_free(kem);
            break;
        }
        case FETCH_PQ_SIGNATURE: {
            EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(ctx, fetch_alg,
                                                     fetch_entries[j].propq);
            if (sig == NULL) {
                fprintf(stderr, "Failed to fetch %s\n", fetch_alg);
                err = 1;
                return;
            }
            EVP_SIGNATURE_free(sig);
            break;
        }
        default:
            err = 1;
            return;
        }
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);
}

static void
usage(const char *progname)
{
    printf("Usage: %s [-t]" PQ_USAGE_OPT " threadcount\n"
           "-t - terse output\n"
           PQ_USAGE_DESC,
           progname);
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    size_t total_count = 0;
    double av;
    int terse = 0;
    size_t i;
    int j;
    int rc = EXIT_FAILURE;
    char *fetch_type = getenv("EVP_FETCH_TYPE");
    int opt;

    while ((opt = getopt(argc, argv, "t" PQ_GETOPT)) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
#ifdef OPENSSL_DO_PQ
        case 'q':
            pq = 1;
            break;
#endif
        default:
            usage(basename(argv[0]));
            return EXIT_FAILURE;
        }
    }

    if (fetch_type != NULL) {
        exclusive_fetch_alg = strstr(fetch_type, ":");
        if (exclusive_fetch_alg == NULL) {
            printf("Malformed EVP_FETCH_TYPE TYPE:ALG\n");
            return EXIT_FAILURE;
        }
        /* Split the string into a type and alg */
        *exclusive_fetch_alg = '\0';
        exclusive_fetch_alg++;
        for (i = 0; i < ARRAY_SIZE(type_map); i++) {
            if (type_map[i] != NULL && !strcmp(fetch_type, type_map[i])) {
                exclusive_fetch_type = i;
                break;
            }
        }
        if (i == ARRAY_SIZE(type_map)) {
            printf("EVP_FETCH_TYPE is invalid\n");
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        printf("threadcount is missing\n");
        return EXIT_FAILURE;
    }
    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        printf("threadcount must be > 0\n");
        return EXIT_FAILURE;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL)
        return EXIT_FAILURE;

    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        printf("Failed to create counts array\n");
        return EXIT_FAILURE;
    }

    if (!perflib_run_multi_thread_test(do_fetch, threadcount, &duration)) {
        printf("Failed to run the test\n");
        goto out;
    }

    if (err) {
        printf("Error during test\n");
        goto out;
    }

    for (j = 0; j < threadcount; j++)
        total_count += counts[j];

    /*
     * EVP_fetch_* calls are pretty fast, running in
     * only a few us.  But ossl_time2us does integer division
     * and so because the average us computed above is less than
     * the value of OSSL_TIME_US, we wind up with truncation to
     * zero in the math.  Instead, manually do the division, casting
     * our values as doubles so that we compute the proper time
     */
    av = (double)RUN_TIME * 1e6 * threadcount / total_count;

    if (terse)
        printf("%lf\n", av);
    else
        printf("Average time per fetch call: %lfus\n", av);

    rc = EXIT_SUCCESS;
out:
    OSSL_LIB_CTX_free(ctx);
    OPENSSL_free(counts);
    return rc;
}
