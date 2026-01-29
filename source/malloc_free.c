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
#include <openssl/crypto.h>
#include "perflib/perflib.h"

#define RUN_TIME 5

int err = 0;

size_t num_calls;
static int threadcount;
size_t *counts;
static size_t min_size = 0;
static size_t max_size = 20;

EVP_PKEY *pkey = NULL;
OSSL_TIME max_time;

void do_malloc_free(size_t num)
{
    OSSL_TIME time;
    size_t alloc_sz;
    void *obj;
    size_t mysize = min_size;

    counts[num] = 0;

    do {

        alloc_sz = 1 << mysize;
        mysize = (mysize + 1) % max_size;
        mysize = (mysize < min_size) ? min_size : mysize;

        obj = OPENSSL_malloc(alloc_sz);
        OPENSSL_free(obj);
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

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

static void report_result(int terse)
{
    if (err) {
        fprintf(stderr, "Error during test\n");
        exit(EXIT_FAILURE);
    }

    if (terse)
        printf("%lf\n", get_avcalltime());
    else
        printf("Average time per malloc/free call: %lfus\n",
            get_avcalltime());
}

static void usage(char * const argv[])
{
    fprintf(stderr, "%s [options] <threadcount>\n", argv[0]);
    fprintf(stderr, "-s - min allocation size\n");
    fprintf(stderr, "-l - max allocation size\n");
    fprintf(stderr, "-V - print version information and exit\n");
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    int terse = 0;
    int rc = EXIT_FAILURE;
    int opt;

    while ((opt = getopt(argc, argv, "s:l:tV")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 's':
            min_size = strtoul(optarg, NULL, 0);
            break;
        case 'l':
            max_size = strtoul(optarg, NULL, 0);
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

    counts = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (counts == NULL) {
        printf("Failed to create counts array\n");
        return EXIT_FAILURE;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (!perflib_run_multi_thread_test(do_malloc_free, threadcount, &duration)) {
        fprintf(stderr, "Failed to run the test\n");
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    report_result(terse);

    if (err) {
        printf("Error during test\n");
        goto out;
    }

    rc = EXIT_SUCCESS;
out:
    OPENSSL_free(counts);
    return rc;
}
