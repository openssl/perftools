/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Perf test for X509_STORE_add_cert() and X509_STORE_add_crl().
 *
 * The store keys objects by their subject/issuer X509_NAME into a hash
 * table (crypto/x509/x509_lu.c); each bucket is a STACK_OF(X509_OBJECT).
 * The cost of an add therefore depends entirely on how the names
 * distribute over the buckets:
 *
 *   spread  - every object carries a distinct name, so it lands in a
 *             bucket of its own.  x509_store_add_obj() does a hash lookup
 *             plus a duplicate check against a ~1-element stack: O(1).
 *
 *   bucket  - every object carries the SAME name, so all of them collide
 *             into one stack, whose growth dominates the add cost.  This is
 *             the pathological case (e.g. many cross-signed certs sharing
 *             one subject), and the interesting one to compare across
 *             implementations.
 *
 * Both modes insert a mix of certs and CRLs.  For each store size N the
 * test repeatedly fills a fresh X509_STORE with the same pre-built objects
 * and reports the best ns-per-add over several trials; only the add loop is
 * timed (store creation/free is excluded).
 *
 * Besides the human-readable summary on stdout, -d writes a gnuplot data
 * file (columns: N spread bucket, in ns/add, for the modes measured) so
 * results from different builds can be plotted against each other; -l
 * records a label in the file header to identify the build (e.g. "baseline"
 * vs "patched").  Use -m both to fill all columns.  See x509storeadd.gnuplot.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif  /* _WIN32 */
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include "perflib/perflib.h"

#define TRIALS 5

#define MIN_ELAPSED ossl_us2time(100)

#define MAX_SIZES 64

static const size_t default_sizes[] = { 128, 512, 2048, 8192, 16384, 32768 };

typedef struct item_st {
    int is_crl;
    X509 *cert;
    X509_CRL *crl;
} ITEM;

/* Shared signing key -- Ed25519: fast keygen and signing, no digest. */
static EVP_PKEY *sign_key = NULL;

/* Deterministic PRNG for the spread-mode shuffle (xorshift32). */
static uint32_t rng_state = 0x12345678u;

static uint32_t rand32(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static X509_NAME *make_name(const char *cn)
{
    X509_NAME *nm = X509_NAME_new();

    if (nm == NULL)
        return NULL;
    if (!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0)) {
        X509_NAME_free(nm);
        return NULL;
    }
    return nm;
}

static X509 *make_cert(const char *cn, long serial)
{
    X509 *x = X509_new();
    X509_NAME *nm = make_name(cn);

    if (x == NULL || nm == NULL)
        goto err;
    if (!X509_set_version(x, X509_VERSION_3)
        || !ASN1_INTEGER_set(X509_get_serialNumber(x), serial)
        || X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 3600) == NULL
        || !X509_set_subject_name(x, nm)
        || !X509_set_issuer_name(x, nm)
        || !X509_set_pubkey(x, sign_key)
        || X509_sign(x, sign_key, NULL) == 0)
        goto err;
    X509_NAME_free(nm);
    return x;

err:
    X509_NAME_free(nm);
    X509_free(x);
    return NULL;
}

static X509_CRL *decode_crl(X509_CRL *c)
{
    X509_CRL *ret = NULL;
    unsigned char *der = NULL, *p;
    const unsigned char *q;
    int len;

    len = i2d_X509_CRL(c, NULL);
    if (len <= 0)
        goto end;

    der = OPENSSL_malloc(len);
    if (der == NULL)
        goto end;

    p = der;
    if (i2d_X509_CRL(c, &p) != len)
        goto end;

    q = der;
    ret = d2i_X509_CRL(NULL, &q, len);

end:
    OPENSSL_free(der);
    return ret;
}

static X509_CRL *make_crl(const char *cn, long tweak)
{
    X509_CRL *c = X509_CRL_new();
    X509_CRL *decoded = NULL;
    X509_NAME *nm = make_name(cn);
    ASN1_TIME *tm = NULL;

    if (c == NULL || nm == NULL)
        goto err;
    /* Vary lastUpdate so same-issuer CRLs are distinct objects. */
    if ((tm = X509_gmtime_adj(NULL, tweak)) == NULL)
        goto err;
    if (!X509_CRL_set_version(c, X509_CRL_VERSION_2)
        || !X509_CRL_set_issuer_name(c, nm)
        || !X509_CRL_set1_lastUpdate(c, tm)
        || X509_CRL_sign(c, sign_key, NULL) == 0)
        goto err;
    /*
     * X509_CRL_match() compares cached SHA-1 fingerprints.  Decode once so
     * programmatically generated CRLs carry the same cache as loaded CRLs.
     */
    if ((decoded = decode_crl(c)) == NULL)
        goto err;

    ASN1_TIME_free(tm);
    X509_NAME_free(nm);
    X509_CRL_free(c);

    return decoded;

err:
    ASN1_TIME_free(tm);
    X509_NAME_free(nm);
    X509_CRL_free(decoded);
    X509_CRL_free(c);
    return NULL;
}

static void free_items(ITEM *items, size_t n)
{
    size_t i;

    if (items == NULL)
        return;
    for (i = 0; i < n; i++) {
        X509_free(items[i].cert);
        X509_CRL_free(items[i].crl);
    }
    OPENSSL_free(items);
}

/*
 * Build n cert/CRL items.
 *
 * spread (shared == NULL): each object gets a unique name so it lands in its
 * own bucket, and insertion order is randomised -- this is the "randomly
 * insert both" workload.
 *
 * single bucket (shared != NULL): every object reuses |shared|, so all land
 * in one bucket.  Objects are grouped by type (all certs, then all CRLs) and
 * deliberately NOT shuffled.  The store's per-bucket duplicate check scans
 * the contiguous run of same-type objects, so grouping hits the worst case
 * deterministically and makes the timing reproducible and monotonic in n.
 * A random cert/CRL interleaving would instead splinter the bucket into
 * short same-type runs whose scan cost depends on the seed, giving wildly
 * non-monotonic timings (e.g. a "lucky" seed looks O(1) per add).
 */
static ITEM *build_items(size_t n, const char *shared)
{
    ITEM *items = OPENSSL_zalloc(n * sizeof(*items));
    size_t ncert = (n + 1) / 2;
    char cn[64];
    size_t i;

    if (items == NULL)
        return NULL;

    for (i = 0; i < n; i++) {
        const char *name;
        int is_crl;

        if (shared != NULL) {
            name = shared;
            is_crl = i >= ncert; /* grouped: certs first, then CRLs */
        } else {
            BIO_snprintf(cn, sizeof(cn), "perf-%s-%zu",
                (i & 1) ? "crl" : "cert", i);
            name = cn;
            is_crl = (int)(i & 1); /* alternating */
        }

        items[i].is_crl = is_crl;
        if (is_crl) {
            items[i].crl = make_crl(name, (long)i + 1);
            if (items[i].crl == NULL)
                goto err;
        } else {
            items[i].cert = make_cert(name, (long)i + 1);
            if (items[i].cert == NULL)
                goto err;
        }
    }

    /* Randomise insertion order only for the spread ("random") workload. */
    if (shared == NULL) {
        for (i = n - 1; i > 0; i--) {
            size_t j = (size_t)(rand32() % (i + 1));
            ITEM tmp = items[i];

            items[i] = items[j];
            items[j] = tmp;
        }
    }

    return items;

err:
    free_items(items, n);
    return NULL;
}

static int add_all(X509_STORE *st, const ITEM *items, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (items[i].is_crl) {
            if (!X509_STORE_add_crl(st, items[i].crl))
                return 0;
        } else {
            if (!X509_STORE_add_cert(st, items[i].cert))
                return 0;
        }
    }

    return 1;
}

static double measure_add(const ITEM *items, size_t n)
{
    double best = -1;
    int t;

    for (t = 0; t < TRIALS; t++) {
        OSSL_TIME elapsed = ossl_time_zero();
        size_t ops = 0;
        double ns;

        do {
            X509_STORE *st = X509_STORE_new();
            OSSL_TIME start, end;

            if (st == NULL)
                return -1;
            start = ossl_time_now();
            if (!add_all(st, items, n)) {
                X509_STORE_free(st);
                return -1;
            }
            end = ossl_time_now();
            X509_STORE_free(st);
            elapsed = ossl_time_add(elapsed, ossl_time_subtract(end, start));
            ops += n;
        } while (ossl_time_compare(elapsed, MIN_ELAPSED) < 0);
        ns = (double)ossl_time2ticks(elapsed) / (double)ops;
        if (best < 0 || ns < best)
            best = ns;
    }

    return best;
}

static void usage(const char *progname)
{
    printf("Usage: %s [-t] [-V] [-m mode] [-n sizes] [-d datfile] [-l label]\n",
           progname);
    printf("-t - terse output\n");
    printf("-V - print version information and exit\n");
    printf("-m - name distribution: spread (default), bucket or both\n");
    printf("-n - comma-separated list of store sizes to sweep\n");
    printf("     (default 128,512,2048,8192,16384,32768)\n");
    printf("-d - write gnuplot data file\n");
    printf("-l - build label recorded in the data file header\n");
}

static size_t parse_sizes(char *list, size_t *sizes)
{
    size_t nsizes = 0;
    char *tok;

    for (tok = strtok(list, ","); tok != NULL; tok = strtok(NULL, ",")) {
        int val = atoi(tok);

        if (val < 1 || nsizes >= MAX_SIZES)
            return 0;
        sizes[nsizes++] = (size_t)val;
    }

    return nsizes;
}

/*
 * Measure one workload for one size: build the items, time the adds, free
 * the items.  Returns ns/add, or -1 on error.
 */
static double run_one(size_t n, const char *shared)
{
    ITEM *items = build_items(n, shared);
    double ns;

    if (items == NULL) {
        printf("Failed to build cert/CRL objects\n");
        return -1;
    }
    ns = measure_add(items, n);
    free_items(items, n);

    return ns;
}

int main(int argc, char *argv[])
{
    size_t sizes[MAX_SIZES];
    size_t nsizes = 0;
    size_t s;
    int terse = 0;
    const char *mode = "spread";
    int do_spread = 0, do_bucket = 0;
    const char *datpath = NULL;
    const char *label = "unlabelled";
    FILE *dat = NULL;
    int ret = EXIT_FAILURE;
    int opt;

    while ((opt = getopt(argc, argv, "tVm:n:d:l:")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        case 'm':
            mode = optarg;
            break;
        case 'n':
            nsizes = parse_sizes(optarg, sizes);
            if (nsizes == 0) {
                printf("sizes must be a comma-separated list of up to %d"
                       " positive integers\n", MAX_SIZES);
                return EXIT_FAILURE;
            }
            break;
        case 'd':
            datpath = optarg;
            break;
        case 'l':
            label = optarg;
            break;
        default:
            usage(basename(argv[0]));
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] != NULL) {
        printf("unexpected argument: %s\n", argv[optind]);
        usage(basename(argv[0]));
        return EXIT_FAILURE;
    }

    if (strcasecmp(mode, "spread") == 0) {
        do_spread = 1;
    } else if (strcasecmp(mode, "bucket") == 0) {
        do_bucket = 1;
    } else if (strcasecmp(mode, "both") == 0) {
        do_spread = do_bucket = 1;
    } else {
        printf("mode must be spread, bucket or both\n");
        usage(basename(argv[0]));
        return EXIT_FAILURE;
    }

    if (nsizes == 0) {
        memcpy(sizes, default_sizes, sizeof(default_sizes));
        nsizes = ARRAY_SIZE(default_sizes);
    }

    sign_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (sign_key == NULL) {
        printf("Failed to generate signing key\n");
        goto err;
    }

    if (datpath != NULL) {
        dat = fopen(datpath, "w");
        if (dat == NULL) {
            printf("Failed to open %s for writing\n", datpath);
            goto err;
        }
        /* gnuplot data file: comment lines start with '#', whitespace cols. */
        fprintf(dat, "# X509_STORE add performance -- ns per add,"
                " best of %d trials\n", TRIALS);
        fprintf(dat, "# build: %s\n", label);
        fprintf(dat, "# columns (NaN = mode not measured):\n");
        fprintf(dat, "#   N       number of cert/CRL objects inserted\n");
        fprintf(dat, "#   spread  distinct names, one per hash bucket\n");
        fprintf(dat, "#   bucket  all objects share a single name"
                " (one bucket)\n");
        fprintf(dat, "#%-9s %14s %14s\n", "N", "spread", "bucket");
    }

    if (!terse)
        printf("X509_STORE_add_cert/add_crl (%s) -- best of %d trials\n",
               mode, TRIALS);

    for (s = 0; s < nsizes; s++) {
        size_t n = sizes[s];
        double spread_ns = 0, bucket_ns = 0;

        if (do_spread) {
            spread_ns = run_one(n, NULL);
            if (spread_ns < 0)
                goto err;
            if (terse)
                printf("%lf\n", spread_ns);
            else
                printf("  spread N=%-8zu %10.1f ns/add\n", n, spread_ns);
        }
        if (do_bucket) {
            bucket_ns = run_one(n, "common-name");
            if (bucket_ns < 0)
                goto err;
            if (terse)
                printf("%lf\n", bucket_ns);
            else
                printf("  bucket N=%-8zu %10.1f ns/add\n", n, bucket_ns);
        }

        if (dat != NULL) {
            fprintf(dat, "%-10zu", n);
            if (do_spread)
                fprintf(dat, " %14.1f", spread_ns);
            else
                fprintf(dat, " %14s", "NaN");
            if (do_bucket)
                fprintf(dat, " %14.1f", bucket_ns);
            else
                fprintf(dat, " %14s", "NaN");
            fprintf(dat, "\n");
        }
    }

    if (dat != NULL && !terse)
        printf("gnuplot data written to %s (label: %s)\n", datpath, label);

    ret = EXIT_SUCCESS;

 err:
    if (dat != NULL)
        fclose(dat);
    EVP_PKEY_free(sign_key);

    return ret;
}
