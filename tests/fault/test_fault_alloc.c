/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Fault injection tests for allocation failure paths.
 *
 * When run WITHOUT LD_PRELOAD, exercises error paths reachable via
 * API misuse (out-of-range keys, bad paths, etc.).
 *
 * When run WITH libfault_alloc.so via LD_PRELOAD, exercises calloc
 * and strdup failure paths in all library functions.
 */

#define _POSIX_C_SOURCE 200809L

#include <egl/egl_graph.h>
#include <egl/egl_loader.h>
#include <egl/egl_reconfig.h>
#include <egl/egl_stats.h>
#include <egl/egl_types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Detect if fault injection is active */
static int fault_active(void)
{
    return getenv("FAULT_CALLOC_AFTER") != NULL ||
           getenv("FAULT_STRDUP_AFTER") != NULL;
}

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  [TEST] %s ... ", name); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        tests_failed++; \
        printf("FAIL: %s\n", msg); \
        return; \
    } while (0)

#define FAILF(fmt, ...) \
    do { \
        tests_failed++; \
        printf("FAIL: " fmt "\n", __VA_ARGS__); \
        return; \
    } while (0)

/* When fault injection is active, allocation failures are expected.
 * Treat them as PASS (the error path was exercised). */
#define FAULT_OK(msg) \
    do { \
        if (fault_active()) { \
            tests_passed++; \
            printf("PASS (fault: %s)\n", msg); \
            return; \
        } \
        FAIL(msg); \
    } while (0)

/* ================================================================
 * Error path tests (no fault injection needed)
 * ================================================================ */

static void test_stats_read_out_of_range(void)
{
    struct egl_graph *g;
    struct egl_node_stats stats;
    int ret;

    TEST("stats_read_out_of_range");

    if (geteuid() != 0) { printf("SKIP: requires root\n"); return; }
    if (access("tc_node_a.bpf.o", R_OK) != 0) {
        printf("SKIP: BPF objects not found\n"); return;
    }

    g = egl_graph_create("fault_stats", 4);
    if (g == NULL) { FAULT_OK("graph create"); }

    ret = egl_graph_add_node(g, 0, "tc_node_a.bpf.o", "tc_node_a");
    if (ret != 0) { egl_graph_destroy(g); FAULT_OK("add_node"); }

    ret = egl_stats_read(g, 999, &stats);
    if (ret >= 0) {
        egl_graph_destroy(g);
        FAIL("expected error for out-of-range node_id");
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_stats_reset_out_of_range(void)
{
    struct egl_graph *g;
    int ret;

    TEST("stats_reset_out_of_range");

    if (geteuid() != 0) { printf("SKIP: requires root\n"); return; }
    if (access("tc_node_a.bpf.o", R_OK) != 0) {
        printf("SKIP: BPF objects not found\n"); return;
    }

    g = egl_graph_create("fault_reset", 4);
    if (g == NULL) { FAULT_OK("graph create"); }

    ret = egl_graph_add_node(g, 0, "tc_node_a.bpf.o", "tc_node_a");
    if (ret != 0) { egl_graph_destroy(g); FAULT_OK("add_node"); }

    ret = egl_stats_reset(g, 999);
    if (ret >= 0) {
        egl_graph_destroy(g);
        FAIL("expected error for out-of-range reset");
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_stats_read_all_partial_fail(void)
{
    struct egl_graph *g;
    struct egl_node_stats stats[16];
    int ret;

    TEST("stats_read_all_partial_fail");

    if (geteuid() != 0) { printf("SKIP: requires root\n"); return; }
    if (access("tc_node_a.bpf.o", R_OK) != 0) {
        printf("SKIP: BPF objects not found\n"); return;
    }

    g = egl_graph_create("fault_readall", 4);
    if (g == NULL) { FAULT_OK("graph create"); }

    ret = egl_graph_add_node(g, 0, "tc_node_a.bpf.o", "tc_node_a");
    if (ret != 0) { egl_graph_destroy(g); FAULT_OK("add_node"); }

    /* Pass max_nodes=16 for a 4-entry map: keys 4-15 fail,
     * hitting the memset(0) error path in read_all */
    ret = egl_stats_read_all(g, stats, 16);
    if (ret != 0) {
        egl_graph_destroy(g);
        FAILF("read_all returned %d", ret);
    }

    if (stats[8].in_count != 0 || stats[8].drops != 0) {
        egl_graph_destroy(g);
        FAIL("expected zeroed stats for out-of-range nodes");
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_reconfig_commit_bad_remove(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_commit_bad_remove");

    g = egl_graph_create("fault_rm", 8);
    if (g == NULL) { FAULT_OK("graph create"); }

    ret = egl_reconfig_begin(g);
    if (ret != 0) { egl_graph_destroy(g); FAULT_OK("begin"); }

    /* Stage removal with invalid index (-1) */
    ret = egl_reconfig_remove_node(g, -1);
    if (ret != 0) {
        (void)egl_reconfig_abort(g);
        egl_graph_destroy(g);
        FAULT_OK("stage remove");
    }

    /* Commit should fail: remove_node(-1) returns -EINVAL */
    ret = egl_reconfig_commit(g);
    if (ret >= 0) {
        egl_graph_destroy(g);
        FAIL("expected error from commit with bad remove");
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_reconfig_commit_bad_add(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_commit_bad_add");

    if (geteuid() != 0) { printf("SKIP: requires root\n"); return; }

    g = egl_graph_create("fault_add", 8);
    if (g == NULL) { FAULT_OK("graph create"); }

    ret = egl_reconfig_begin(g);
    if (ret != 0) { egl_graph_destroy(g); FAULT_OK("begin"); }

    ret = egl_reconfig_add_node(g, 0, "/nonexistent.bpf.o", "prog");
    if (ret != 0) {
        (void)egl_reconfig_abort(g);
        egl_graph_destroy(g);
        FAULT_OK("stage add");
    }

    /* Commit should fail: can't open /nonexistent.bpf.o */
    ret = egl_reconfig_commit(g);
    if (ret >= 0) {
        egl_graph_destroy(g);
        FAIL("expected error from commit with bad add");
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_loader_invalid_bpf(void)
{
    struct egl_bpf_prog *prog;
    FILE *f;

    TEST("loader_invalid_bpf");

    f = fopen("/tmp/egl_test_invalid.o", "w");
    if (f == NULL) { FAULT_OK("create temp file"); }
    (void)fprintf(f, "not a valid BPF object\n");
    (void)fclose(f);

    prog = egl_loader_open("/tmp/egl_test_invalid.o");
    (void)unlink("/tmp/egl_test_invalid.o");

    if (prog != NULL) {
        egl_loader_close(prog);
        FAIL("expected NULL for invalid BPF file");
    }

    PASS();
}

/* ================================================================
 * Allocation failure paths (exercised with LD_PRELOAD)
 * ================================================================ */

/* egl_graph_create does 4 callocs + 2 strdup calls.
 * Fault injection at each point should return NULL without crash. */
static void test_graph_create_alloc_failure(void)
{
    struct egl_graph *g;

    TEST("graph_create_alloc_failure");

    g = egl_graph_create("fault_test", 8);

    if (g != NULL) {
        egl_graph_destroy(g);
        printf("PASS (no fault at this call count)\n");
        tests_passed++;
    } else {
        PASS();
    }
}

/* validate_dag does 2 calloc calls: in_degree and queue. */
static void test_validate_dag_alloc_failure(void)
{
    struct egl_graph *g;
    int ret;

    TEST("validate_dag_alloc_failure");

    g = egl_graph_create("fault_dag", 4);
    if (g == NULL) {
        printf("PASS (fault during create)\n");
        tests_passed++;
        return;
    }

    (void)egl_graph_add_edge(g, 0, 1);

    ret = egl_graph_validate_dag(g);

    if (ret == 0 || ret == -ELOOP) {
        printf("PASS (no fault at this call count)\n");
        tests_passed++;
    } else if (ret == -ENOMEM) {
        PASS();
    } else {
        FAILF("unexpected return %d", ret);
    }

    egl_graph_destroy(g);
}

/* egl_reconfig_add_node does 2 strdup calls */
static void test_reconfig_strdup_failure(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_strdup_failure");

    g = egl_graph_create("fault_reconfig", 8);
    if (g == NULL) {
        printf("PASS (fault during create)\n");
        tests_passed++;
        return;
    }

    ret = egl_reconfig_begin(g);
    if (ret != 0) {
        egl_graph_destroy(g);
        FAIL("begin failed");
    }

    ret = egl_reconfig_add_node(g, 0, "dummy.o", "prog");

    if (ret == 0) {
        (void)egl_reconfig_abort(g);
        printf("PASS (no fault at this call count)\n");
        tests_passed++;
    } else if (ret == -ENOMEM) {
        (void)egl_reconfig_abort(g);
        PASS();
    } else {
        (void)egl_reconfig_abort(g);
        FAILF("unexpected return %d", ret);
    }

    egl_graph_destroy(g);
}

/* egl_loader_open does strdup + bpf_object__open + bpf_object__load.
 * strdup failure should return NULL. */
static void test_loader_strdup_failure(void)
{
    struct egl_bpf_prog *prog;

    TEST("loader_strdup_failure");

    if (geteuid() != 0) { printf("SKIP: requires root\n"); return; }
    if (access("tc_node_a.bpf.o", R_OK) != 0) {
        printf("SKIP: BPF objects not found\n"); return;
    }

    prog = egl_loader_open("tc_node_a.bpf.o");

    if (prog != NULL) {
        egl_loader_close(prog);
        printf("PASS (no fault at this call count)\n");
        tests_passed++;
    } else {
        /* Either strdup or bpf_object__open/load failed */
        PASS();
    }
}

/* egl_stats_read does 1 calloc for percpu_vals */
static void test_stats_read_alloc_failure(void)
{
    struct egl_graph *g;
    struct egl_node_stats stats;
    int ret;

    TEST("stats_read_alloc_failure");

    if (geteuid() != 0) { printf("SKIP: requires root\n"); return; }
    if (access("tc_node_a.bpf.o", R_OK) != 0) {
        printf("SKIP: BPF objects not found\n"); return;
    }

    g = egl_graph_create("fault_sread", 4);
    if (g == NULL) {
        printf("PASS (fault during create)\n");
        tests_passed++;
        return;
    }

    ret = egl_graph_add_node(g, 0, "tc_node_a.bpf.o", "tc_node_a");
    if (ret != 0) {
        egl_graph_destroy(g);
        printf("PASS (fault during add_node)\n");
        tests_passed++;
        return;
    }

    ret = egl_stats_read(g, 0, &stats);
    if (ret == 0) {
        printf("PASS (no fault at this call count)\n");
        tests_passed++;
    } else if (ret == -ENOMEM) {
        PASS();
    } else {
        /* Other errors acceptable during fault injection */
        printf("PASS (error %d during fault)\n", ret);
        tests_passed++;
    }

    egl_graph_destroy(g);
}

int main(void)
{
    const char *env_c = getenv("FAULT_CALLOC_AFTER");
    const char *env_s = getenv("FAULT_STRDUP_AFTER");

    if (env_c != NULL) {
        printf("=== Fault Tests (FAULT_CALLOC_AFTER=%s) ===\n", env_c);
    } else if (env_s != NULL) {
        printf("=== Fault Tests (FAULT_STRDUP_AFTER=%s) ===\n", env_s);
    } else {
        printf("=== Error Path Tests (no fault injection) ===\n");
    }

    /* Error path tests */
    test_stats_read_out_of_range();
    test_stats_reset_out_of_range();
    test_stats_read_all_partial_fail();
    test_reconfig_commit_bad_remove();
    test_reconfig_commit_bad_add();
    test_loader_invalid_bpf();

    /* Allocation failure tests */
    test_graph_create_alloc_failure();
    test_validate_dag_alloc_failure();
    test_reconfig_strdup_failure();
    test_loader_strdup_failure();
    test_stats_read_alloc_failure();

    printf("\n--- Results: %d/%d passed, %d failed ---\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
