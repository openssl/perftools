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
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include "perflib/perflib.h"

#define NUM_CALLS_PER_TEST         100000

size_t num_calls;
static int err = 0;
OSSL_TIME *times;

static int doit(OSSL_PROVIDER *provider, void *vcount)
{
    int *count = vcount;

    (*count)++;
    return 1;
}

static int threadcount;

static void do_providerdoall(size_t num)
{
    size_t i;
    int count;
    OSSL_TIME start, end;

    start = ossl_time_now();

    for (i = 0; i < num_calls / threadcount; i++) {
        count = 0;
        if (!OSSL_PROVIDER_do_all(NULL, doit, &count) || count != 1) {
            err = 1;
            break;
        }
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);
}

int main(int argc, char *argv[])
{
    int i;
    OSSL_TIME duration, ttime;
    double av;
    int terse = 0;
    int ret = EXIT_FAILURE;
    int opt;

    while ((opt = getopt(argc, argv, "t")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        default:
            printf("Usage: %s [-t] threadcount\n", basename(argv[0]));
            printf("-t - terse output\n");
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
    num_calls = NUM_CALLS_PER_TEST;
    if (NUM_CALLS_PER_TEST % threadcount > 0) /* round up */
        num_calls += threadcount - NUM_CALLS_PER_TEST % threadcount;

    times = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (times == NULL) {
        printf("Failed to create times array\n");
        goto err;
    }

    if (!perflib_run_multi_thread_test(do_providerdoall, threadcount, &duration)) {
        printf("Failed to run the test\n");
        goto err;
    }

    if (err) {
        printf("Error during test\n");
        goto err;
    }

    ttime = times[0];
    for (i = 1; i < threadcount; i++)
        ttime = ossl_time_add(ttime, times[i]);

    av = ((double)ossl_time2ticks(ttime) / num_calls) / (double)OSSL_TIME_US;

    if (terse)
        printf("%lf\n", av);
    else
        printf("Average time per OSSL_PROVIDER_do_all() call: %lfus\n",
               av);

    ret = EXIT_SUCCESS;
 err:
    OPENSSL_free(times);
    return ret;
}
