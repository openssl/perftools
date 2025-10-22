/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
# include <dirent.h>
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif	/* _WIN32 */
#include <openssl/bio.h>
#include <openssl/x509.h>
#include "perflib/err.h"
#include "perflib/perflib.h"

#define RUN_TIME 5
#define QUANTILES 5
#define NONCE_CFG "file:servercert.pem"
#define CTX_SHARE_THREADS 1

static size_t timeout_us = RUN_TIME * 1000000;
static size_t quantiles = QUANTILES;

enum verbosity {
    VERBOSITY_TERSE,
    VERBOSITY_DEFAULT,
    VERBOSITY_VERBOSE,
    VERBOSITY_DEBUG_STATS,
    VERBOSITY_DEBUG,

    VERBOSITY_MAX__
};

enum nonce_type {
    NONCE_PATH,
};

struct call_times {
    uint64_t duration;
    uint64_t total_count;
    uint64_t total_found;
    uint64_t min_count;
    uint64_t max_count;
    double avg;
    double min;
    double max;
    double stddev;
    double median;
    size_t min_idx;
    size_t max_idx;
};

struct nonce_cfg {
    enum nonce_type type;
    const char *path;
    char **dirs;
    size_t num_dirs;
};

struct thread_data {
    OSSL_TIME start_time;
    struct {
        uint64_t count;
        uint64_t found;
        OSSL_TIME end_time;
    } *q_data;
    X509_STORE_CTX *ctx;
} *thread_data;

static int error = 0;
static int verbosity = VERBOSITY_DEFAULT;
static X509_STORE *store = NULL;
static X509 *x509_nonce = NULL;

static int threadcount;

OSSL_TIME max_time;

#define OSSL_MIN(p, q) ((p) < (q) ? (p) : (q))
#define OSSL_MAX(p, q) ((p) > (q) ? (p) : (q))

static X509 *
load_cert_from_file(const char *path)
{
    BIO *bio = BIO_new_file(path, "rb");
    X509 *x509 = NULL;

    if (bio == NULL) {
        warnx("Unable to create BIO for reading \"%s\"", path);
        return NULL;
    }

    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        if (verbosity >= VERBOSITY_DEBUG)
            warnx("Failed to read certificate \"%s\"", path);
    }

    BIO_free(bio);

    return x509;
}

static bool
is_abs_path(const char *path)
{
    if (path == NULL)
        return false;

#if defined(_WIN32)
    /*
     * So, we don't try to concatenate the provided path with the directory
     * paths if the path starts with the following:
     *  - volume character and a colon ("C:"):  it is either absolute path
     *    (if followed by a backslash), or a relative path to a current
     *    directory of that volume (and we don't want to implement any logic
     *    that handles that);
     *  - backslash ("\"):  it is an "absolute path" on the "current" drive,
     *    or (if there are two backslashes in the beginning) an UNC path.
     */
    return (isalpha(path[0]) && path[1] == ':') || path[0] == '\\';
#else /* !_WIN32 */
    return path[0] == '/';
#endif
}

static X509 *
load_nonce_from_path(struct nonce_cfg *cfg)
{
    if (is_abs_path(cfg->path))
        return load_cert_from_file(cfg->path);

    for (size_t i = 0; i < cfg->num_dirs; i++) {
        char *cert;
        X509 *ret;

        cert = perflib_mk_file_path(cfg->dirs[i], cfg->path);
        if (cert == NULL) {
            warnx("Failed to allocate file path for directory \"%s\""
                  " and path \"%s\"", cfg->dirs[i], cfg->path);
            continue;
        }

        ret = load_cert_from_file(cert);
        OPENSSL_free(cert);

        if (ret != NULL)
            return ret;
    }

    return NULL;
}

static X509 *
make_nonce(struct nonce_cfg *cfg)
{
    switch (cfg->type) {
    case NONCE_PATH:
        return load_nonce_from_path(cfg);
    default:
        errx(EXIT_FAILURE, "Unknown nonce type: %lld", (long long) cfg->type);
    }
}

static size_t
read_cert(const char * const dir, const char * const name, X509_STORE * const store)
{
    X509 *x509 = NULL;
    char *path = NULL;
    size_t ret = 0;

    path = perflib_mk_file_path(dir, name);
    if (path == NULL) {
        warn("Failed to allocate cert name in directory \"%s\" for file \"%s\"",
             dir, name);
        goto out;
    }

    x509 = load_cert_from_file(path);
    if (x509 == NULL) {
        goto out;
    }

    if (!X509_STORE_add_cert(store, x509)) {
        warnx("Failed to add a certificate from \"%s\" to the store\n", path);
        goto out;
    }

    if (verbosity >= VERBOSITY_DEBUG)
        fprintf(stderr, "Successfully added a certificate from \"%s\""
                " to the store\n", path);

    ret = 1;

 out:
    X509_free(x509);
    OPENSSL_free(path);

    return ret;
}

#if defined(_WIN32)
static size_t
read_certsdir(char * const dir, X509_STORE * const store)
{
    const size_t dir_len = strlen(dir);
    const size_t glob_len = dir_len + sizeof("\\*");
    size_t cnt = 0;
    char *search_glob = NULL;
    HANDLE find_handle = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA find_data;
    DWORD last_err;

    search_glob = OPENSSL_malloc(glob_len);
    if (search_glob == NULL) {
        warnx("Error allocating a search glob for \"%s\"", dir);
        return 0;
    }

    if (snprintf(search_glob, glob_len, "%s\\*", dir) != glob_len - 1) {
        warnx("Error generating a search glob for \"%s\"", dir);
        goto out;
    }

    find_handle = FindFirstFileA(search_glob, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        warnx("Error in FindFirstFile(): %#lx", GetLastError());
        goto out;
    }

    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (verbosity >= VERBOSITY_DEBUG)
                warnx("\"%s\\%s\" is a directory file, skipping",
                      dir, find_data.cFileName);
            continue;
        }

        cnt += read_cert(dir, find_data.cFileName, store);

    } while (FindNextFileA(find_handle, &find_data) != 0);

    last_err = GetLastError();
    if (last_err != ERROR_NO_MORE_FILES)
        warnx("Error in FindNextFile(): %#lx", last_err);

 out:
    if (find_handle != INVALID_HANDLE_VALUE)
        FindClose(find_handle);
    OPENSSL_free(search_glob);

    return cnt;
}
#else /* !defined(_WIN32) */
static size_t
read_certsdir(char * const dir, X509_STORE * const store)
{
    struct dirent *e;
    DIR *d = opendir(dir);
    size_t cnt = 0;

    if (d == NULL) {
        warn("Could not open \"%s\"", dir);

        return 0;
    }

    while (1) {
        errno = 0;
        e = readdir(d);

        if (e == NULL) {
            if (errno != 0)
                warn("An error occurred while reading directory \"%s\"", dir);

            break;
        }

        if (e->d_type != DT_REG && e->d_type != DT_UNKNOWN) {
            if (verbosity >= VERBOSITY_DEBUG)
                warnx("\"%s/%s\" is not a regular file, skipping",
                      dir, e->d_name);
            continue;
        }

        cnt += read_cert(dir, e->d_name, store);
    }

    closedir(d);

    return cnt;
}
#endif /* defined(_WIN32) */

static size_t
read_certsdirs(char * const * const dirs, const int dir_cnt,
               X509_STORE * const store)
{
    size_t cnt = 0;

    for (int i = 0; i < dir_cnt; i++)
        cnt += read_certsdir(dirs[i], store);

    return cnt;
}

static void
do_x509storeissuer(size_t num)
{
    struct thread_data *td = &thread_data[num];
    X509 *issuer = NULL;
    OSSL_TIME time;
    OSSL_TIME duration;
    OSSL_TIME q_end;
    size_t q = 0;
    size_t count = 0;
    size_t found = 0;

    td->start_time = ossl_time_now();
    duration.t = max_time.t - td->start_time.t;
    q_end.t = duration.t / quantiles + td->start_time.t;

    do {
        if (X509_STORE_CTX_get1_issuer(&issuer, td->ctx, x509_nonce) != 0) {
            found++;
            X509_free(issuer);
        }
        issuer = NULL;
        count++;
        time = ossl_time_now();
        if (time.t >= q_end.t) {
            td->q_data[q].count = count;
            td->q_data[q].found = found;
            td->q_data[q].end_time = time;
            q_end.t = (duration.t * (++q + 1)) / quantiles + td->start_time.t;
        }
    } while (time.t < max_time.t);

    td->q_data[quantiles - 1].count = count;
    td->q_data[quantiles - 1].found = found;
    td->q_data[quantiles - 1].end_time = time;
}

static void
report_store_size(X509_STORE * const store, const char * const suffix,
                  int verbosity)
{
    if (verbosity >= VERBOSITY_DEBUG_STATS) {
        STACK_OF(X509_OBJECT) *sk =
#if OPENSSL_VERSION_NUMBER >= 0x30300000L
            X509_STORE_get1_objects(store);
#else
            X509_STORE_get0_objects(store);
#endif

        fprintf(stderr, "Number of certificates in the store %s: %d\n",
                suffix, sk_X509_OBJECT_num(sk));

#if OPENSSL_VERSION_NUMBER >= 0x30300000L
        sk_X509_OBJECT_pop_free(sk, X509_OBJECT_free);
#endif
    }
}

static int
cmp_double(const void *a_ptr, const void *b_ptr)
{
    const double * const a = a_ptr;
    const double * const b = b_ptr;

    return *a - *b < 0 ? -1 : *a - *b > 0 ? 1 : 0;
}

static void
get_calltimes(struct call_times *times, int verbosity)
{
    double *thread_times;

    for (size_t q = 0; q < quantiles; q++) {
        for (size_t i = 0; i < threadcount; i++) {
            uint64_t start_t = q ? thread_data[i].q_data[q - 1].end_time.t
                                 : thread_data[i].start_time.t;
            uint64_t count = thread_data[i].q_data[q].count -
                (q ? thread_data[i].q_data[q - 1].count : 0);
            uint64_t found = thread_data[i].q_data[q].found -
                (q ? thread_data[i].q_data[q - 1].found : 0);

            times[q].duration += thread_data[i].q_data[q].end_time.t - start_t;
            times[q].total_count += count;
            times[q].total_found += found;
        }
    }

    for (size_t q = 0; q < quantiles; q++) {
        times[quantiles].duration += times[q].duration;
        times[quantiles].total_count += times[q].total_count;
        times[quantiles].total_found += times[q].total_found;
    }

    for (size_t q = (quantiles == 1); q <= quantiles; q++)
        times[q].avg = (double) times[q].duration / OSSL_TIME_US / times[q].total_count;

    if (verbosity >= VERBOSITY_VERBOSE) {
        thread_times = OPENSSL_zalloc(threadcount * sizeof(*thread_times));

        for (size_t q = (quantiles == 1); q <= quantiles; q++) {
            double variance = 0;

            for (size_t i = 0; i < threadcount; i++) {
                uint64_t start_t = q && q != quantiles
                    ? thread_data[i].q_data[q - 1].end_time.t
                    : thread_data[i].start_time.t;
                uint64_t duration =
                    thread_data[i].q_data[OSSL_MIN(q, quantiles - 1)].end_time.t
                    - start_t;
                uint64_t count =
                    thread_data[i].q_data[OSSL_MIN(q, quantiles - 1)].count -
                    (q && q != quantiles ? thread_data[i].q_data[q - 1].count
                                         : 0);
                thread_times[i] = (double) duration / OSSL_TIME_US / count;
            }

            times[q].min = times[q].max = thread_times[0];
            times[q].min_idx = times[q].max_idx = 0;

            for (size_t i = 0; i < threadcount; i++) {
                if (thread_times[i] < times[q].min) {
                    times[q].min = thread_times[i];
                    times[q].min_idx = i;
                }

                if (thread_times[i] > times[q].max) {
                    times[q].max = thread_times[i];
                    times[q].max_idx = i;
                }
            }

            qsort(thread_times, threadcount, sizeof(thread_times[0]), cmp_double);
            times[q].median = thread_times[threadcount / 2];

            for (size_t i = 0; i < threadcount; i++) {
                double dev = thread_times[i] - times[q].avg;

                variance += dev * dev;
            }

            times[q].stddev = sqrt(variance / threadcount);
        }

        OPENSSL_free(thread_times);
    }
}

static void
report_result(int verbosity)
{
    struct call_times *times;

    times = OPENSSL_zalloc(sizeof(*times) * (quantiles + 1));

    get_calltimes(times, verbosity);

    switch (verbosity) {
    case VERBOSITY_TERSE:
        printf("%lf\n", times[1].avg);
        break;
    case VERBOSITY_DEFAULT:
        printf("Average time per call: %lfus\n", times[1].avg);
        break;
    case VERBOSITY_VERBOSE:
    default:
        /* if quantiles == 1, we only need to print total runtime info */
        for (size_t i = (quantiles == 1); i <= quantiles; i++) {
            if (i < quantiles)
                printf("Part %8zu", i + 1);
            else
                printf("Total runtime");

            printf(": avg: %9.3lf us, median: %9.3lf us"
                   ", min: %9.3lf us @thread %3zu, max: %9.3lf us @thread %3zu"
                   ", stddev: %9.3lf us (%8.4lf%%)"
                   ", hits %9" PRIu64 " of %9" PRIu64 " (%8.4lf%%)\n",
                   times[i].avg, times[i].median,
                   times[i].min, times[i].min_idx,
                   times[i].max, times[i].max_idx,
                   times[i].stddev,
                   100.0 * times[i].stddev / times[i].avg,
                   times[i].total_found, times[i].total_count,
                   100.0 * times[i].total_found / (times[i].total_count));
        }
        break;
    }

    OPENSSL_free(times);
}

static void
usage(char * const argv[])
{
    fprintf(stderr,
            "Usage: %s [-t] [-v] [-q N] [-T time] [-n nonce_type:type_args]"
            " [-C threads] [-V] certsdir [certsdir...] threadcount\n"
            "\t-t\tTerse output\n"
            "\t-v\tVerbose output.  Multiple usage increases verbosity.\n"
            "\t-q\tGather information about temporal N-quantiles.\n"
            "\t\tDone only when the output is verbose.  Default: "
            OPENSSL_MSTR(QUANTILES) "\n"
            "\t-T\tTimeout for the test run in seconds,\n"
            "\t\tcan be fractional.  Default: "
            OPENSSL_MSTR(RUN_TIME) "\n"
            "\t-n\tNonce configuration, supported options:\n"
            "\t\t\tfile:PATH - load nonce certificate from PATH;\n"
            "\t\t\tif PATH is relative, the provided certsdir's are searched.\n"
            "\t\tDefault: " NONCE_CFG "\n"
            "\t-C\tNumber of threads that share the same X.509\n"
            "\t\tstore context object.  Default: "
            OPENSSL_MSTR(CTX_SHARE_THREADS) "\n"
            "\t-V\tprint version information and exit\n"
            , basename(argv[0]));
}

static size_t
parse_timeout(const char * const optarg)
{
    char *endptr = NULL;
    double timeout_s;

    timeout_s = strtod(optarg, &endptr);

    if (endptr == NULL || *endptr != '\0' || timeout_s < 0)
        errx(EXIT_FAILURE, "incorrect timeout value: \"%s\"", optarg);

    if (timeout_s > SIZE_MAX / 1000000)
        errx(EXIT_FAILURE, "timeout is too large: %f", timeout_s);

    return (size_t)(timeout_s * 1e6);
}

/**
 * Parse nonce configuration string. Currently supported formats:
 *  * "file:PATH" - where PATH is either a relative path (that will be then
 *                  checked against the list of directories provided),
 *                  or an absolute one.
 */
static void
parse_nonce_cfg(const char * const optarg, struct nonce_cfg *cfg)
{
    static const char file_pfx[] = "file:";

    if (strncmp(optarg, file_pfx, sizeof(file_pfx) - 1) == 0) {
        cfg->type = NONCE_PATH;
        cfg->path = optarg + sizeof(file_pfx) - 1;
    } else {
        errx(EXIT_FAILURE, "incorrect nonce configuration: \"%s\"", optarg);
    }
}

static long long
parse_int(const char * const s, long long min, long long max,
          const char * const what)
{
    char *endptr = NULL;
    long long ret;

    ret = strtoll(s, &endptr, 0);
    if (endptr == NULL || *endptr != '\0')
        errx(EXIT_FAILURE, "failed to parse %s as a number: \"%s\"", what, s);
    if (ret < min || ret > max)
        errx(EXIT_FAILURE, "provided value of %s is out of the expected"
                           " %lld..%lld range: %lld", what, min, max, ret);

    return ret;
}

int
main(int argc, char *argv[])
{
    OSSL_TIME duration;
    size_t ctx_share_cnt = CTX_SHARE_THREADS;
    int ret = EXIT_FAILURE;
    int opt;
    int dirs_start;
    size_t num_certs = 0;
    struct nonce_cfg nonce_cfg;

    parse_nonce_cfg(NONCE_CFG, &nonce_cfg);

    while ((opt = getopt(argc, argv, "tvq:T:n:C:V")) != -1) {
        switch (opt) {
        case 't': /* terse */
            verbosity = VERBOSITY_TERSE;
            break;
        case 'v': /* verbose */
            if (verbosity < VERBOSITY_VERBOSE) {
                verbosity = VERBOSITY_VERBOSE;
            } else {
                if (verbosity < VERBOSITY_MAX__ - 1)
                    verbosity++;
            }
            break;
        case 'q': /* quantiles */
            quantiles = parse_int(optarg, 1, INT_MAX,
                                  "number of quantiles");
            break;
        case 'T': /* timeout */
            timeout_us = parse_timeout(optarg);
            break;
        case 'n': /* nonce */
            parse_nonce_cfg(optarg, &nonce_cfg);
            break;
        case 'C': /* how many threads share X509_STORE_CTX */
            ctx_share_cnt = parse_int(optarg, 1, INT_MAX,
                                      "X509_STORE_CTX share degree");
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            usage(argv);
            return EXIT_FAILURE;
        }
    }

    if (verbosity < VERBOSITY_VERBOSE)
        quantiles = 1;

    if (argv[optind] == NULL)
        errx(EXIT_FAILURE, "certsdir is missing");

    dirs_start = optind++;

    /*
     * Store the part of argv containing directories to nonce_cfg so
     * load_nonce_from_path can use it later.
     */
    nonce_cfg.dirs = argv + dirs_start;
    nonce_cfg.num_dirs = argc - 1 - dirs_start;

    if (optind >= argc)
        errx(EXIT_FAILURE, "threadcount is missing");

    threadcount = parse_int(argv[argc - 1], 1, INT_MAX, "threadcount");

    thread_data = OPENSSL_zalloc(threadcount * sizeof(*thread_data));
    if (thread_data == NULL)
        errx(EXIT_FAILURE, "Failed to create thread_data array");

    for (size_t i = 0; i < threadcount; i++) {
        thread_data[i].q_data = OPENSSL_zalloc(quantiles *
                                               sizeof(*(thread_data[i].q_data)));
        if (thread_data[i].q_data == NULL)
            errx(EXIT_FAILURE, "Failed to create quantiles array for thread"
                               " %zu", i);
    }

    store = X509_STORE_new();
    if (store == NULL || !X509_STORE_set_default_paths(store))
        errx(EXIT_FAILURE, "Failed to create X509_STORE");

    num_certs += read_certsdirs(argv + dirs_start, argc - dirs_start - 1,
                                store);

    if (verbosity >= VERBOSITY_DEBUG_STATS)
        fprintf(stderr, "Added %zu certificates to the store\n", num_certs);

    report_store_size(store, "before the test run", verbosity);

    x509_nonce = make_nonce(&nonce_cfg);
    if (x509_nonce == NULL)
        errx(EXIT_FAILURE, "Unable to create the nonce X509 object");

    for (size_t i = 0; i < threadcount; i++) {
        if (i % ctx_share_cnt) {
            thread_data[i].ctx = thread_data[i - i % ctx_share_cnt].ctx;
        } else {
            thread_data[i].ctx = X509_STORE_CTX_new();
            if (thread_data[i].ctx == NULL
                || !X509_STORE_CTX_init(thread_data[i].ctx, store, x509_nonce,
                                        NULL))
                errx(EXIT_FAILURE, "Failed to initialise X509_STORE_CTX"
                     " for thread %zu", i);
        }
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_us2time(timeout_us));

    if (!perflib_run_multi_thread_test(do_x509storeissuer, threadcount, &duration))
        errx(EXIT_FAILURE, "Failed to run the test");

    if (error)
        errx(EXIT_FAILURE, "Error during test");

    report_result(verbosity);

    ret = EXIT_SUCCESS;

    X509_free(x509_nonce);
    X509_STORE_free(store);
    if (thread_data != NULL) {
        for (size_t i = 0; i < threadcount; i++) {
            if (!(i % ctx_share_cnt))
                X509_STORE_CTX_free(thread_data[i].ctx);
            OPENSSL_free(thread_data[i].q_data);
        }
    }
    OPENSSL_free(thread_data);
    return ret;
}
