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
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif	/* _WIN32 */
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "perflib/perflib.h"

#define RUN_TIME 5

int error = 0;
EVP_PKEY *rsakey = NULL;

size_t *counts;
OSSL_TIME max_time;

static const char *rsakeypem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEwggE9AgEAAkEAwmjwpbuKfvtBTAiQ\n"
    "U4OWjPVo0WM1UGGh9EJwgTnJm43l0HwL3GjmPBmToqhUYE6zfWi9jOpQkCSpDnIR\n"
    "1Pc18QIDAQABAkEAsKZmNFIK8IMhvBL0Ac7J19+OlOSOpzFv1eEhFWsK9FoNnsV/\n"
    "4Z4KlISNB+b7M5OJxYs4AutQIKr6zmlT7lk7OQIhAPj/LPWwkk+Ts2pBB64CokZ0\n"
    "C7GCeloMiPc3mCxsWbbnAiEAx+C6ham16nvvVUnYjoWSpNTuAhV61+FR0xKLk797\n"
    "iWcCIQCEy1KnFaxyVEtzd4so+q6g9HLoELZAID9L2ZKG3qJaMQIhAJFIU8tb9BKg\n"
    "SvJfXr0ZceHFs8pn+oZ4DJWzYSjfgdf5AiEAmk7Kt7Y8qPVJwb5bJL5CkoBxRwzS\n"
    "jHZXmRwpxC4tAFo=\n"
    "-----END PRIVATE KEY-----\n";

static const char *tbs = "0123456789abcdefghij"; /* Length of SHA1 digest */

static int threadcount;

void do_rsasign(size_t num)
{
    unsigned char sig[64];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsakey, NULL);
    size_t siglen = sizeof(sig);
    OSSL_TIME time;

    counts[num] = 0;

    do {
        if (EVP_PKEY_sign_init(ctx) <= 0
                || EVP_PKEY_sign(ctx, sig, &siglen, (const unsigned char*)tbs,
                                 SHA_DIGEST_LENGTH) <= 0) {
            error = 1;
            break;
        }
        counts[num]++;
        time = ossl_time_now();
    } while(time.t < max_time.t);

    EVP_PKEY_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    size_t total_count = 0;
    double avcalltime;
    int terse = 0;
    BIO *membio = NULL;
    int rc = EXIT_FAILURE;
    int i;
    int opt;

    while ((opt = getopt(argc, argv, "tV")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            printf("Usage: %s [-t] [-V] threadcount\n", basename(argv[0]));
            printf("-t - terse output\n");
            printf("-V - print version information and exit\n");
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

    assert(strlen(tbs) == SHA_DIGEST_LENGTH);
    membio = BIO_new_mem_buf(rsakeypem, strlen(rsakeypem));
    if (membio == NULL) {
        printf("Failed to create internal BIO\n");
        return EXIT_FAILURE;
    }
    rsakey = PEM_read_bio_PrivateKey(membio, NULL, NULL, NULL);
    BIO_free(membio);
    if (rsakey == NULL) {
        printf("Failed to load the RSA key\n");
        goto out;
    }

    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    if (counts == NULL) {
        printf("Failed to create counts array\n");
        goto out;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (!perflib_run_multi_thread_test(do_rsasign, threadcount, &duration)) {
        printf("Failed to run the test\n");
        goto out;
    }

    if (error) {
        printf("Error during test\n");
        goto out;
    }

    for (i = 0; i < threadcount; i++)
        total_count += counts[i];

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;

    if (terse)
        printf("%lf\n", avcalltime);
    else
        printf("Average time per RSA signature operation: %lfus\n",
               avcalltime);

    rc = EXIT_SUCCESS;

out:
    EVP_PKEY_free(rsakey);
    OPENSSL_free(counts);
    return rc;
}
