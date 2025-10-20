/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
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
#define NONCE_CFG "file:servercert.pem"

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

struct nonce_cfg {
    enum nonce_type type;
    const char *path;
    char **dirs;
    size_t num_dirs;
};

static int error = 0;
static int verbosity = VERBOSITY_DEFAULT;
static X509_STORE *store = NULL;
static X509 *x509_nonce = NULL;

static int threadcount;

size_t *counts;
OSSL_TIME max_time;

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

static void
do_x509storeissuer(size_t num)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509 *issuer = NULL;
    OSSL_TIME time;

    if (ctx == NULL || !X509_STORE_CTX_init(ctx, store, x509_nonce, NULL)) {
        warnx("Failed to initialise X509_STORE_CTX");
        error = 1;
        goto err;
    }

    counts[num] = 0;

    do {
        /*
         * We actually expect this to fail. We've not configured any
         * certificates inside our store. We're just testing calling this
         * against an empty store.
         */
        if (X509_STORE_CTX_get1_issuer(&issuer, ctx, x509_nonce) != 0) {
            warnx("Unexpected result from X509_STORE_CTX_get1_issuer");
            error = 1;
            X509_free(issuer);
            goto err;
        }
        issuer = NULL;
        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

 err:
    X509_STORE_CTX_free(ctx);
}

static void
usage(char * const argv[])
{
    fprintf(stderr,
            "Usage: %s [-t] [-v] [-n nonce_type:type_args]"
            " [-V] certsdir threadcount\n"
            "\t-t\tTerse output\n"
            "\t-n\tNonce configuration, supported options:\n"
            "\t\t\tfile:PATH - load nonce certificate from PATH;\n"
            "\t\t\tif PATH is relative, the provided certsdir's are searched.\n"
            "\t\tDefault: " NONCE_CFG "\n"
            "\t-V\tprint version information and exit\n"
            , basename(argv[0]));
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
    int i;
    OSSL_TIME duration;
    size_t total_count = 0;
    double avcalltime;
    char *cert = NULL;
    int ret = EXIT_FAILURE;
    BIO *bio = NULL;
    int opt;
    int dirs_start;
    struct nonce_cfg nonce_cfg;

    parse_nonce_cfg(NONCE_CFG, &nonce_cfg);

    while ((opt = getopt(argc, argv, "tvn:V")) != -1) {
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
        case 'n': /* nonce */
            parse_nonce_cfg(optarg, &nonce_cfg);
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            usage(argv);
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL)
        errx(EXIT_FAILURE, "certsdir is missing");

    dirs_start = optind++;

    /*
     * Store the part of argv containing directories to nonce_cfg so
     * load_nonce_from_path can use it later.
     */
    nonce_cfg.dirs = argv + dirs_start;
    nonce_cfg.num_dirs = 1;

    if (argv[optind] == NULL)
        errx(EXIT_FAILURE, "threadcount is missing");

    threadcount = parse_int(argv[optind], 1, INT_MAX, "threadcount");

    store = X509_STORE_new();
    if (store == NULL || !X509_STORE_set_default_paths(store))
        errx(EXIT_FAILURE, "Failed to create X509_STORE");

    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    if (counts == NULL)
        errx(EXIT_FAILURE, "Failed to create counts array");

    x509_nonce = make_nonce(&nonce_cfg);
    if (x509_nonce == NULL)
        errx(EXIT_FAILURE, "Unable to create the nonce X509 object");

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (!perflib_run_multi_thread_test(do_x509storeissuer, threadcount, &duration))
        errx(EXIT_FAILURE, "Failed to run the test");

    if (error)
        errx(EXIT_FAILURE, "Error during test");

    for (i = 0; i < threadcount; i++)
        total_count += counts[i];

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;

    switch (verbosity) {
    case VERBOSITY_TERSE:
        printf("%lf\n", avcalltime);
        break;
    default:
        printf("Average time per X509_STORE_CTX_get1_issuer() call: %lfus\n",
               avcalltime);
    }

    ret = EXIT_SUCCESS;

    X509_free(x509_nonce);
    X509_STORE_free(store);
    BIO_free(bio);
    OPENSSL_free(cert);
    OPENSSL_free(counts);
    return ret;
}
