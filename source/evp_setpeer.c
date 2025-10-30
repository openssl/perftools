/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
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
# include "perflib/basename.h"
# include "perflib/getopt.h"
#endif	/* _WIN32 */
#include <openssl/evp.h>
#include "perflib/perflib.h"

/* run 'make regen_key_samples' if header file is missing */
#include "keys_setpeer.h"

#define RUN_TIME 5

int err = 0;

size_t num_calls;
static int threadcount;
size_t *counts;

EVP_PKEY *pkey = NULL;
OSSL_TIME max_time;

void do_setpeer(size_t num)
{
    size_t i;
    OSSL_TIME time;

    EVP_PKEY_CTX *pkey_ctx = NULL;

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        err = 1;
        printf("Failed to create pkey_ctx\n");
        return;
    }

    if (EVP_PKEY_derive_init(pkey_ctx) <= 0) {
        err = 1;
        printf("Failed to init pkey_ctx\n");
        EVP_PKEY_CTX_free(pkey_ctx);
        return;
    }

    counts[num] = 0;

    do {
        if (EVP_PKEY_derive_set_peer(pkey_ctx, pkey) <= 0) {
            err = 1;
            break;
        }
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

    EVP_PKEY_CTX_free(pkey_ctx);
}

static int sample_name_to_id(const char *sample_name)
{
    int i = 0;

    while (sample_names[i] != NULL) {
        if (strcasecmp(sample_names[i], sample_name) == 0)
            break;
        i++;
    }

    return i;
}

static double get_avcalltime(void)
{
    int i;
    size_t total_count = 0;
    double avcalltime;

    for (i = 0; i < threadcount; i++)
        total_count += counts[i];

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;

    return avcalltime;
}

static void report_result(int key_id, int terse)
{
    if (err) {
        fprintf(stderr, "Error during test of %s\n",
                sample_names[key_id]);
        exit(EXIT_FAILURE);
    }

    if (terse)
        printf("%lf\n", get_avcalltime());
    else
        printf("Average time per %s evp_set_peer call: %lfus\n",
            sample_names[key_id], get_avcalltime());
}

static void usage(char * const argv[])
{
    const char **key_name = sample_names;

    fprintf(stderr, "%s -k key_name [-t] [-V] threadcount\n", argv[0]);
    fprintf(stderr, "-t - terse output\n");
    fprintf(stderr, "-k - one of these options: %s", *key_name);

    do {
        key_name++;
        if (*key_name == NULL)
            fprintf(stderr, "\n");
        else
            fprintf(stderr, ", %s", *key_name);
    } while (*key_name != NULL);

    fprintf(stderr, "-V - print version information and exit\n");
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    int terse = 0;
    int rc = EXIT_FAILURE;
    size_t i;
    int opt;

    char *key = NULL;
    int key_id, key_id_min, key_id_max, k;

    while ((opt = getopt(argc, argv, "k:tV")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 'k':
            key = optarg;
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            usage(argv);
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        fprintf(stderr, "Missing threadcount argument\n");
        usage(argv);
        return EXIT_FAILURE;
    }

    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        fprintf(stderr, "threadcount must be > 0\n");
        usage(argv);
        return EXIT_FAILURE;
    }

    if (key == NULL) {
        fprintf(stderr, "option -k is missing\n");
        usage(argv);
        return EXIT_FAILURE;
    }

    key_id = sample_name_to_id(key);
    if (key_id == SAMPLE_INVALID) {
        fprintf(stderr, "Unknown key name (%s)\n", key);
        return EXIT_FAILURE;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    counts = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (counts == NULL) {
        printf("Failed to create counts array\n");
        return EXIT_FAILURE;
    }

    if (key_id == SAMPLE_ALL) {
        key_id_min = 0;
        key_id_max = SAMPLE_ALL;
    } else {
        key_id_min = key_id;
        key_id_max = key_id + 1;
    }

    /* run key types as appropriate */
    for (k = key_id_min; k < key_id_max; k++) {
        const char *keydata;
        size_t keydata_sz;
        BIO *pem;

        keydata = sample_keys[k];
        keydata_sz = sample_key_sizes[k];

        pem = BIO_new_mem_buf(keydata, keydata_sz);
        if (pem == NULL) {
            fprintf(stderr, "%s Cannot create mem BIO [%s PEM]\n",
                    __func__, sample_names[k]);
            return EXIT_FAILURE;
        }

        pkey = PEM_read_bio_PrivateKey(pem, NULL, NULL, NULL);
        BIO_free(pem);
        if (pkey == NULL) {
            fprintf(stderr, "Failed to create key: %llu [%s PEM]\n",
                    (unsigned long long)i,
                    sample_names[k]);
            return EXIT_FAILURE;
        }

        if (!perflib_run_multi_thread_test(do_setpeer, threadcount, &duration)) {
            fprintf(stderr, "Failed to run the test %s\n", sample_names[k]);
            EVP_PKEY_free(pkey);
            return EXIT_FAILURE;
        }

        report_result(k, terse);
        EVP_PKEY_free(pkey);
    }

    if (err) {
        printf("Error during test\n");
        goto out;
    }

    rc = EXIT_SUCCESS;
out:
    OPENSSL_free(counts);
    return rc;
}
