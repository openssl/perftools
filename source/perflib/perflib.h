/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PERFLIB_PERFLIB_H
# define OSSL_PERFLIB_PERFLIB_H
# pragma once

#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "perflib/time.h"

# if defined(_WIN32)

#  include <windows.h>

typedef HANDLE thread_t;
typedef DWORD_PTR affinity_t;

#  define strcasecmp(_a, _b) _stricmp((_a), (_b))

# else

#  include <pthread.h>

typedef pthread_t thread_t;
typedef unsigned long affinity_t;

# endif

struct thread_arg_st {
    void (*func)(size_t num);
    size_t num;
};

/**
 * A callback that allows setting CPU affinity for the threads being run.
 * Gets the set of available CPUs in the cpu_set argument and expected
 * to update it in accordance with the information provided in num and arg
 * arguments.
 *
 * Currently supported only on glibc on Linux (because of a non-privileged
 * pthread_attr_setaffinity_np, with a maximum of 1024 CPUs) and Windows
 * (with a limitation of using only the initial process group).
 *
 * @param[in,out] cpu_set       On entering, contains the set of CPUs available
 *                              to the test.  The callback is supposed
 *                              to update the set in accordance
 *                              with the information provided in num, cnt,
 *                              and arg parameters.
 * @param[in]     cpu_set_bits  Size of cpu_set_bits, in bits.
 * @param[in]     num           Index of a thread index being run,
 *                              counted from 0.
 * @param[in]     cnt           Total count of available CPUs
 *                              (popcnt(cpu_set_bits)).
 * @param         arg           An opaque pointer that a caller has provided
 *                              along the callback.
 * @return                      1 on success, 0 on error.
 */
typedef int (*perflib_affinity_fn)(affinity_t *cpu_set, size_t cpu_set_bits,
                                   size_t num, size_t cnt, void *arg);

/**
 * A simple affinity callback that assigns each thread a single CPU
 * in a round robin fashion.  arg must be NULL.
 */
int perflib_roundrobin_affinity(affinity_t *cpu_set_bits, size_t cpu_set_size,
                                size_t num, size_t cnt, void *arg);

int perflib_run_thread_ex(thread_t *t, struct thread_arg_st *arg,
                          perflib_affinity_fn affinity_cb,
                          void *affinity_cb_arg);
static ossl_unused ossl_inline int
perflib_run_thread(thread_t *t, struct thread_arg_st *arg)
{
    return perflib_run_thread_ex(t, arg, NULL, NULL);
}
int perflib_wait_for_thread(thread_t thread);
int perflib_run_multi_thread_test_ex(void (*f)(size_t), size_t threadcount,
                                     OSSL_TIME *duration,
                                     perflib_affinity_fn affinity_cb,
                                     void *affinity_cb_arg);
static ossl_unused ossl_inline int
perflib_run_multi_thread_test(void (*f)(size_t), size_t threadcount,
                              OSSL_TIME *duration)
{
    return perflib_run_multi_thread_test_ex(f, threadcount, duration,
                                            NULL, NULL);
}
char *perflib_mk_file_path(const char *dir, const char *file);
char *perflib_glue_strings(const char *list[], size_t *out_len);

int perflib_create_ssl_ctx_pair(const SSL_METHOD *sm, const SSL_METHOD *cm,
                                int min_proto_version, int max_proto_version,
                                SSL_CTX **sctx, SSL_CTX **cctx, char *certfile,
                                char *privkeyfile);
int perflib_create_ossl_lib_ctx_pair(OSSL_LIB_CTX *libctx, const SSL_METHOD *sm,
                                     const SSL_METHOD *cm, int min_proto_version,
                                     int max_proto_version, SSL_CTX **sctx, SSL_CTX **cctx,
                                     char *certfile, char *privkeyfile);
int perflib_create_ssl_objects(SSL_CTX *serverctx, SSL_CTX *clientctx,
                               SSL **sssl, SSL **cssl, BIO *s_to_c_fbio,
                               BIO *c_to_s_fbio);
int perflib_create_bare_ssl_connection(SSL *serverssl, SSL *clientssl, int want);
int perflib_create_ssl_connection(SSL *serverssl, SSL *clientssl, int want);
void perflib_shutdown_ssl_connection(SSL *serverssl, SSL *clientssl);

#endif
