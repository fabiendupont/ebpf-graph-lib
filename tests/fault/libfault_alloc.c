/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * LD_PRELOAD fault injection library for calloc and strdup.
 *
 * Environment variables:
 *   FAULT_CALLOC_AFTER=N  — calloc returns NULL after N successful calls
 *   FAULT_STRDUP_AFTER=N  — strdup returns NULL after N successful calls
 *
 * Only intercepts calloc and strdup (not malloc) because libbpf and
 * glibc crash when malloc returns NULL.
 *
 * Usage:
 *   FAULT_CALLOC_AFTER=3 LD_PRELOAD=./libfault_alloc.so ./test_binary
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

static int fault_calloc_after = -1;
static int fault_strdup_after = -1;
static int calloc_count = 0;
static int strdup_count = 0;
static int initialized = 0;

/* Small static buffer for bootstrap allocations before dlsym resolves */
static char bootstrap_buf[8192];
static size_t bootstrap_used = 0;

static void *(*real_calloc)(size_t, size_t) = NULL;
static char *(*real_strdup)(const char *) = NULL;

static void init_fault(void)
{
    const char *env;

    if (initialized) { return; }
    initialized = 1;

    env = getenv("FAULT_CALLOC_AFTER");
    if (env != NULL) { fault_calloc_after = atoi(env); }

    env = getenv("FAULT_STRDUP_AFTER");
    if (env != NULL) { fault_strdup_after = atoi(env); }
}

void *calloc(size_t nmemb, size_t size)
{
    if (real_calloc == NULL) {
        /* Bootstrap: dlsym may call calloc internally. */
        size_t total = nmemb * size;
        void *p;

        if (bootstrap_used + total > sizeof(bootstrap_buf)) {
            return NULL;
        }

        p = &bootstrap_buf[bootstrap_used];
        bootstrap_used += total;
        memset(p, 0, total);
        return p;
    }

    init_fault();

    if (fault_calloc_after >= 0 && calloc_count >= fault_calloc_after) {
        return NULL;
    }
    calloc_count++;

    return real_calloc(nmemb, size);
}

char *strdup(const char *s)
{
    if (real_strdup == NULL) {
        /* Bootstrap — shouldn't happen but be safe */
        return NULL;
    }

    init_fault();

    if (fault_strdup_after >= 0 && strdup_count >= fault_strdup_after) {
        return NULL;
    }
    strdup_count++;

    return real_strdup(s);
}

/* Resolve real functions after bootstrap */
static void __attribute__((constructor)) resolve_symbols(void)
{
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_strdup = dlsym(RTLD_NEXT, "strdup");
}
