/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <string.h>

#include "perflib/err.h"
#include "perflib/perflib.h"

#define OSSL_NELEM(x) (sizeof(x)/sizeof((x)[0]))

/** affinity_t-typed value with nth bit set. */
#define AFFINITY_BIT(n) ((affinity_t)1U << (n))

#if defined(__GNUC__)

static ossl_inline unsigned int popcount(affinity_t a)
{
    return __builtin_popcountl(a);
}

#else /* !__GNUC__ */

static ossl_inline unsigned int popcount(affinity_t a)
{
    unsigned int ret = 0;

    for (size_t i = 0; i < sizeof(a) * CHAR_BIT; i++)
        ret += (a & AFFINITY_BIT(i)) != 0;

    return ret;
}

#endif /* __GNUC__ */

int perflib_roundrobin_affinity(affinity_t *cpu_set_bits, size_t cpu_set_size,
                                size_t num, size_t cnt, void *arg)
{
    enum { BITS_PER_ELEM = sizeof(cpu_set_bits[0]) * CHAR_BIT };
    size_t set_cnt = 0;
    size_t i;

    if (arg != NULL) {
        WARNX("Non-NULL arg");

        return 0;
    }

    /* Finding (num % cnt)th set bit in the provided mask */
    for (i = 0; i < cpu_set_size; i++) {
        if (cpu_set_bits[i / BITS_PER_ELEM] & AFFINITY_BIT(i % BITS_PER_ELEM))
            set_cnt++;

        if (set_cnt == (num % cnt + 1))
            break;
    }

    if (set_cnt != (num % cnt + 1)) {
        WARNX("Only %zu bits are set in the affinity mask, %zu expected",
              set_cnt, num % cnt + 1);

        return 0;
    }

    memset(cpu_set_bits, 0, cpu_set_size / CHAR_BIT);

    cpu_set_bits[i / BITS_PER_ELEM] = AFFINITY_BIT(i % BITS_PER_ELEM);

    return 1;
}

#if defined(_WIN32)

struct thread_affinity {
    /*
     * It is not a "DWORD *", as any sane person would think, but "__int3264",
     * which is 32-bit wide on 32-bit systems and 64-bit wide on 64-bit ones.
     */
    DWORD_PTR affinity;
};

static DWORD WINAPI thread_run(LPVOID varg)
{
    struct thread_arg_st *arg = varg;

    arg->func(arg->num);

    return 0;
}

static int prepare_affinity_args(perflib_affinity_fn affinity_cb,
                                 void *affinity_cb_arg,
                                 struct thread_affinity *ta,
                                 size_t start, size_t count)
{
    HANDLE process;
    DWORD_PTR dummy;
    unsigned int cnt;

    if (count == 0)
        return 1;

    process = GetCurrentProcess();
    /* TODO: support multiple process groups */
    if (!GetProcessAffinityMask(process, &ta[0].affinity, &dummy)) {
        WARNX("Error getting process affinity mask: %lu", GetLastError());

        return 0;
    }

    cnt = popcount(ta[0].affinity);

    for (size_t i = 1; i < count; i++)
        ta[i].affinity = ta[0].affinity;

    for (size_t i = 0; i < count; i++) {
        if (affinity_cb(&ta[i].affinity, sizeof(DWORD_PTR) * CHAR_BIT,
                        start + i, cnt, affinity_cb_arg) != 1) {
            WARNX("Error calling thread affinity callback for thread %zu",
                  start + i);

            return 0;
        }
    }

    return 1;
}

static void cleanup_affinity_arg(struct thread_affinity *ta,
                                 size_t start, size_t count)
{
}

static int perflib_run_thread_(thread_t *t, struct thread_arg_st *arg,
                               struct thread_affinity *ta)
{
    DWORD thread_id;

    *t = CreateThread(NULL, 0, thread_run, arg, CREATE_SUSPENDED, &thread_id);

    if (t == NULL) {
        WARNX("Error creating thread %zu: %lu", arg->num, GetLastError());
    } else {
        if (!SetThreadAffinityMask(t, ta->affinity))
            WARNX("Error setting thread affinity for thread %zu: %lu",
                  arg->num, GetLastError());
        if (ResumeThread(t) < 0)
            WARNX("Error resuming thread %zu: %lu", arg->num, GetLastError());
    }

    return *t != NULL;
}


int perflib_wait_for_thread(thread_t thread)
{
    return WaitForSingleObject(thread, INFINITE) == 0;
}

#else /* !_WIN32 */

struct thread_affinity {
    pthread_attr_t attr;
};

static void *thread_run(void *varg)
{
    struct thread_arg_st *arg = varg;

    arg->func(arg->num);

    return NULL;
}

# if defined(__linux) && defined(__GLIBC__)
#  include <errno.h>
#  include <pthread.h>
#  include <sched.h>
#  include <unistd.h>

static int prepare_affinity_args_linux(perflib_affinity_fn affinity_cb,
                                       void *affinity_cb_arg,
                                       struct thread_affinity *ta,
                                       size_t start, size_t count)
{
    cpu_set_t process_affinity;
    unsigned int cnt = 0;

    if (!affinity_cb)
        return 1;

    /* TODO: support more than 1024 CPUs */
    if (sched_getaffinity(getpid(), sizeof(process_affinity),
                          &process_affinity) != 0) {
        WARN("sched_getaffinity");

        return 0;
    }

    for (size_t i = 0; i < OSSL_NELEM(process_affinity.__bits); i++)
        cnt += popcount(process_affinity.__bits[i]);

    for (size_t i = 0; i < count; i++) {
        cpu_set_t thread_affinity = process_affinity;
        int ret;

        if (affinity_cb(thread_affinity.__bits,
                        sizeof(thread_affinity) * CHAR_BIT,
                        start + i, cnt, affinity_cb_arg) != 1) {
            WARNX("Error calling thread affinity callback for thread %zu",
                  start + i);

            return 0;
        }

        ret = pthread_attr_setaffinity_np(&ta[i].attr, sizeof(thread_affinity),
                                          &thread_affinity);

        if (ret != 0) {
            WARNX("Error setting thread affinity afttribute for thread %zu",
                  start + i);

            return 0;
        }
	}

    return 1;
}
# endif /* __linux */

static int prepare_affinity_args(perflib_affinity_fn affinity_cb,
                                 void *affinity_cb_arg,
                                 struct thread_affinity *ta,
                                 size_t start, size_t count)
{
    if (count == 0)
        return 1;

    for (size_t i = 0; i < count; i++)
        pthread_attr_init(&ta[i].attr);

# if defined(__linux) && defined(__GLIBC__)
	return prepare_affinity_args_linux(affinity_cb, affinity_cb_arg, ta,
                                       start, count);
# else /* !(__linux && __GLIBC__) */
	/*
     * So far, setting thread affinity is only supported on Linux+glibc on POSIX
     * systems.
     */
    if (affinity_cb) {
        WARNX("Setting thread affinity is not supported in this environment");

        return 0;
    }

    return 1;
# endif
}

static void cleanup_affinity_arg(struct thread_affinity *ta,
                                 size_t start, size_t count)
{
    for (size_t i = 0; i < count; i++)
        pthread_attr_destroy(&ta[i].attr);
}

int perflib_run_thread_(thread_t *t, struct thread_arg_st *arg,
                        struct thread_affinity *ta)
{
    return pthread_create(t, &ta->attr, thread_run, arg) == 0;
}

int perflib_wait_for_thread(thread_t thread)
{
    return pthread_join(thread, NULL) == 0;
}

#endif /* _WIN32 */

int perflib_run_thread_ex(thread_t *t, struct thread_arg_st *arg,
                          perflib_affinity_fn affinity_cb,
                          void *affinity_cb_arg)
{
    struct thread_affinity ta;

    prepare_affinity_args(affinity_cb, affinity_cb_arg, &ta, arg->num, 1);

    return perflib_run_thread_(t, arg, &ta);
}

int perflib_run_multi_thread_test_ex(void (*f)(size_t), size_t threadcount,
                                     OSSL_TIME *duration,
                                     perflib_affinity_fn affinity_cb,
                                     void *affinity_cb_arg)
{
    OSSL_TIME start, end;
    thread_t *threads = NULL;
    int *run_threads = NULL;
    struct thread_arg_st *args = NULL;
    struct thread_affinity *ta = NULL;
    size_t i;
    int ret = 0;

    threads = OPENSSL_malloc(sizeof(*threads) * threadcount);
    if (threads == NULL) {
        WARN("Could not allocate threads array");

        goto err;
    }

    run_threads = OPENSSL_zalloc(sizeof(*run_threads) * threadcount);
    if (run_threads == NULL) {
        WARN("Could not allocate run_threads array");

        goto err;
    }

    args = OPENSSL_malloc(sizeof(*args) * threadcount);
    if (args == NULL) {
        WARN("Could not allocate args array");

        goto err;
    }

    ta = OPENSSL_malloc(sizeof(*ta) * threadcount);
    if (ta == NULL) {
        WARN("Could not allocate args array");

        goto err;
    }
    if (!prepare_affinity_args(affinity_cb, affinity_cb_arg,
                               ta, 0, threadcount))
        goto err;

    start = ossl_time_now();
    ret = 1;

    for (i = 0; i < threadcount; i++) {
        args[i].func = f;
        args[i].num = i;
        if (!(run_threads[i] = perflib_run_thread_(&threads[i], &args[i],
                                                   ta + i)))
            ret = 0;
    }

    for (i = 0; i < threadcount; i++) {
        if (run_threads[i])
            perflib_wait_for_thread(threads[i]);
    }

    end = ossl_time_now();
    *duration = ossl_time_subtract(end, start);

err:
    OPENSSL_free(ta);
    OPENSSL_free(args);
    OPENSSL_free(run_threads);
    OPENSSL_free(threads);

    return ret;
}
