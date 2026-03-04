/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Integration tests for ebpf-graph-lib.
 *
 * Exercises the full API surface including:
 *   - egl_graph: create, add_node, remove_node, destroy, error paths
 *   - egl_loader: open, get_prog_fd, get_prog_type, pin/reuse maps, close
 *   - egl_reconfig: begin, add_node, remove_node, commit, abort
 *   - egl_stats: read, read_all, reset
 *
 * Requires:
 *   - Root privileges (or CAP_BPF + CAP_NET_ADMIN)
 *   - Pre-compiled BPF objects: tc_node_a.bpf.o, tc_node_b.bpf.o, tc_node_c.bpf.o
 *   - Run from the directory containing the BPF objects
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
static int tests_skipped = 0;

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

#define SKIP(msg) \
    do { \
        tests_skipped++; \
        printf("SKIP: %s\n", msg); \
        return; \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        int _a = (a); \
        int _b = (b); \
        if (_a != _b) { \
            FAILF("%s == %s (%d != %d)", #a, #b, _a, _b); \
        } \
    } while (0)

#define ASSERT_GE(a, b) \
    do { \
        int _a = (a); \
        int _b = (b); \
        if (_a < _b) { \
            FAILF("%s >= %s (%d < %d)", #a, #b, _a, _b); \
        } \
    } while (0)

static int have_privileges(void)
{
    return geteuid() == 0;
}

static int bpf_obj_exists(const char *path)
{
    return access(path, R_OK) == 0;
}

static const char *NODE_A = "tc_node_a.bpf.o";
static const char *NODE_B = "tc_node_b.bpf.o";
static const char *NODE_C = "tc_node_c.bpf.o";

/* Guard macro for tests that need root + BPF objects */
#define REQUIRE_BPF() \
    do { \
        if (!have_privileges()) { SKIP("requires root"); } \
        if (!bpf_obj_exists(NODE_A) || !bpf_obj_exists(NODE_B) || \
            !bpf_obj_exists(NODE_C)) { \
            SKIP("BPF objects not found"); \
        } \
    } while (0)

/* ================================================================
 * Graph: DAG validation (no BPF required)
 * ================================================================ */

static void test_tc_pipeline_dag(void)
{
    struct egl_graph *g;
    int ret;

    TEST("tc_pipeline_dag_validation");

    g = egl_graph_create("tc_pipeline", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    ret = egl_graph_add_edge(g, 0, 1);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 1, 2);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

static void test_tc_pipeline_cycle_detection(void)
{
    struct egl_graph *g;
    int ret;

    TEST("tc_pipeline_cycle_detection");

    g = egl_graph_create("tc_cycle", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    (void)egl_graph_add_edge(g, 0, 1);
    (void)egl_graph_add_edge(g, 1, 2);
    (void)egl_graph_add_edge(g, 2, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, -ELOOP);

    egl_graph_destroy(g);
    PASS();
}

/* ================================================================
 * Graph: Full BPF loading pipeline
 * ================================================================ */

static void test_tc_pipeline_full(void)
{
    struct egl_graph *g;
    int ret;

    TEST("tc_pipeline_full_load");
    REQUIRE_BPF();

    g = egl_graph_create("tc_full", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    /* Load 3 TC nodes */
    ret = egl_graph_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);

    ret = egl_graph_add_node(g, 1, NODE_B, "tc_node_b");
    ASSERT_EQ(ret, 0);

    ret = egl_graph_add_node(g, 2, NODE_C, "tc_node_c");
    ASSERT_EQ(ret, 0);

    (void)egl_graph_add_edge(g, 0, 1);
    (void)egl_graph_add_edge(g, 1, 2);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    ASSERT_GE(egl_graph_get_prog_array_fd(g), 0);
    ASSERT_GE(egl_graph_get_stats_fd(g), 0);

    /* Remove middle node */
    ret = egl_graph_remove_node(g, 1);
    ASSERT_EQ(ret, 0);

    /* Re-add at same index */
    ret = egl_graph_add_node(g, 1, NODE_B, "tc_node_b");
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* ================================================================
 * Graph: Error paths
 * ================================================================ */

static void test_graph_add_node_duplicate(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_add_node_duplicate");
    REQUIRE_BPF();

    g = egl_graph_create("tc_dup", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    ret = egl_graph_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);

    /* Adding at same index should fail with EEXIST */
    ret = egl_graph_add_node(g, 0, NODE_B, "tc_node_b");
    ASSERT_EQ(ret, -EEXIST);

    egl_graph_destroy(g);
    PASS();
}

static void test_graph_add_node_bad_prog_name(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_add_node_bad_prog_name");
    REQUIRE_BPF();

    g = egl_graph_create("tc_badname", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    /* Valid BPF object but wrong program name */
    ret = egl_graph_add_node(g, 0, NODE_A, "nonexistent_prog");
    if (ret != -ENOENT && ret != -EINVAL) {
        FAILF("expected -ENOENT or -EINVAL, got %d", ret);
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_graph_add_node_bad_file(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_add_node_bad_file");
    REQUIRE_BPF();

    g = egl_graph_create("tc_badfile", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    /* Non-existent BPF object file */
    ret = egl_graph_add_node(g, 0, "/nonexistent.bpf.o", "prog");
    if (ret >= 0) { FAIL("expected error for bad file"); }

    egl_graph_destroy(g);
    PASS();
}

/* ================================================================
 * Loader: standalone API
 * ================================================================ */

static void test_loader_open_close(void)
{
    struct egl_bpf_prog *prog;

    TEST("loader_open_close");
    REQUIRE_BPF();

    prog = egl_loader_open(NODE_A);
    if (prog == NULL) { FAIL("loader_open failed"); }

    egl_loader_close(prog);
    PASS();
}

static void test_loader_null_path(void)
{
    struct egl_bpf_prog *prog;

    TEST("loader_null_path");

    prog = egl_loader_open(NULL);
    if (prog != NULL) {
        egl_loader_close(prog);
        FAIL("expected NULL for NULL path");
    }

    PASS();
}

static void test_loader_bad_path(void)
{
    struct egl_bpf_prog *prog;

    TEST("loader_bad_path");

    prog = egl_loader_open("/nonexistent_file.bpf.o");
    if (prog != NULL) {
        egl_loader_close(prog);
        FAIL("expected NULL for bad path");
    }

    PASS();
}

static void test_loader_get_prog_fd(void)
{
    struct egl_bpf_prog *prog;
    int fd;

    TEST("loader_get_prog_fd");
    REQUIRE_BPF();

    prog = egl_loader_open(NODE_A);
    if (prog == NULL) { FAIL("loader_open failed"); }

    fd = egl_loader_get_prog_fd(prog, "tc_node_a");
    ASSERT_GE(fd, 0);

    /* Non-existent program name */
    fd = egl_loader_get_prog_fd(prog, "no_such_prog");
    ASSERT_EQ(fd, -ENOENT);

    /* NULL args */
    ASSERT_EQ(egl_loader_get_prog_fd(NULL, "tc_node_a"), -EINVAL);
    ASSERT_EQ(egl_loader_get_prog_fd(prog, NULL), -EINVAL);

    egl_loader_close(prog);
    PASS();
}

static void test_loader_get_prog_type(void)
{
    struct egl_bpf_prog *prog;
    int ptype;

    TEST("loader_get_prog_type");
    REQUIRE_BPF();

    prog = egl_loader_open(NODE_A);
    if (prog == NULL) { FAIL("loader_open failed"); }

    ptype = egl_loader_get_prog_type(prog, "tc_node_a");
    /* TC programs are BPF_PROG_TYPE_SCHED_CLS (3) */
    ASSERT_GE(ptype, 0);

    /* Non-existent program */
    ASSERT_EQ(egl_loader_get_prog_type(prog, "no_such"), -ENOENT);

    /* NULL args */
    ASSERT_EQ(egl_loader_get_prog_type(NULL, "tc_node_a"), -EINVAL);
    ASSERT_EQ(egl_loader_get_prog_type(prog, NULL), -EINVAL);

    egl_loader_close(prog);
    PASS();
}

static void test_loader_pin_reuse_maps(void)
{
    struct egl_bpf_prog *prog;
    int ret;
    const char *pin_dir = "/sys/fs/bpf/egl/test_loader_pin";

    TEST("loader_pin_reuse_maps");
    REQUIRE_BPF();

    prog = egl_loader_open(NODE_A);
    if (prog == NULL) { FAIL("loader_open failed"); }

    /* NULL args */
    ASSERT_EQ(egl_loader_pin_maps(NULL, pin_dir), -EINVAL);
    ASSERT_EQ(egl_loader_pin_maps(prog, NULL), -EINVAL);
    ASSERT_EQ(egl_loader_reuse_maps(NULL, pin_dir), -EINVAL);
    ASSERT_EQ(egl_loader_reuse_maps(prog, NULL), -EINVAL);

    /* Pin maps */
    ret = egl_loader_pin_maps(prog, pin_dir);
    ASSERT_EQ(ret, 0);

    /* Reuse from a non-existent pin dir (should silently skip) */
    ret = egl_loader_reuse_maps(prog, "/sys/fs/bpf/egl/nonexistent_dir");
    ASSERT_EQ(ret, 0);

    /* Cleanup: unpin */
    (void)unlink("/sys/fs/bpf/egl/test_loader_pin/egl_prog_array");
    (void)unlink("/sys/fs/bpf/egl/test_loader_pin/egl_node_stats");
    (void)rmdir("/sys/fs/bpf/egl/test_loader_pin");

    egl_loader_close(prog);
    PASS();
}

static void test_loader_close_null(void)
{
    TEST("loader_close_null");

    /* Should not crash */
    egl_loader_close(NULL);

    PASS();
}

/* ================================================================
 * Reconfig: staged reconfiguration
 * ================================================================ */

static void test_reconfig_null_args(void)
{
    TEST("reconfig_null_args");

    ASSERT_EQ(egl_reconfig_begin(NULL), -EINVAL);
    ASSERT_EQ(egl_reconfig_add_node(NULL, 0, "f", "p"), -EINVAL);
    ASSERT_EQ(egl_reconfig_remove_node(NULL, 0), -EINVAL);
    ASSERT_EQ(egl_reconfig_commit(NULL), -EINVAL);
    ASSERT_EQ(egl_reconfig_abort(NULL), -EINVAL);

    PASS();
}

static void test_reconfig_not_active(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_not_active");

    g = egl_graph_create("reconfig_noact", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    /* Operations without begin should fail */
    ret = egl_reconfig_add_node(g, 0, "f.o", "prog");
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_reconfig_remove_node(g, 0);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_reconfig_commit(g);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_reconfig_abort(g);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

static void test_reconfig_begin_abort(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_begin_abort");

    g = egl_graph_create("reconfig_abort", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    /* Stage some operations */
    ret = egl_reconfig_add_node(g, 0, "dummy.o", "prog");
    ASSERT_EQ(ret, 0);

    ret = egl_reconfig_remove_node(g, 1);
    ASSERT_EQ(ret, 0);

    /* Abort discards everything */
    ret = egl_reconfig_abort(g);
    ASSERT_EQ(ret, 0);

    /* Can begin again after abort */
    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    ret = egl_reconfig_abort(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

static void test_reconfig_double_begin(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_double_begin");

    g = egl_graph_create("reconfig_dbl", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    /* Second begin without abort should fail */
    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, -EBUSY);

    ret = egl_reconfig_abort(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

static void test_reconfig_wrong_graph(void)
{
    struct egl_graph *g1;
    struct egl_graph *g2;
    int ret;

    TEST("reconfig_wrong_graph");

    g1 = egl_graph_create("reconfig_g1", 8);
    g2 = egl_graph_create("reconfig_g2", 8);
    if (g1 == NULL || g2 == NULL) { FAIL("graph create failed"); }

    ret = egl_reconfig_begin(g1);
    ASSERT_EQ(ret, 0);

    /* Operations on g2 should fail — reconfig is active for g1 */
    ret = egl_reconfig_add_node(g2, 0, "f.o", "p");
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_reconfig_remove_node(g2, 0);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_reconfig_commit(g2);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_reconfig_abort(g1);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g1);
    egl_graph_destroy(g2);
    PASS();
}

static void test_reconfig_commit_removes(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_commit_removes");
    REQUIRE_BPF();

    g = egl_graph_create("reconfig_rm", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    /* Add two nodes directly */
    ret = egl_graph_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_node(g, 1, NODE_B, "tc_node_b");
    ASSERT_EQ(ret, 0);

    /* Reconfig: remove node 0 */
    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    ret = egl_reconfig_remove_node(g, 0);
    ASSERT_EQ(ret, 0);

    ret = egl_reconfig_commit(g);
    ASSERT_EQ(ret, 0);

    /* Node 0 should be gone; re-adding should succeed */
    ret = egl_graph_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

static void test_reconfig_commit_adds(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_commit_adds");
    REQUIRE_BPF();

    g = egl_graph_create("reconfig_add", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    /* Reconfig: add two nodes */
    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    ret = egl_reconfig_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);

    ret = egl_reconfig_add_node(g, 1, NODE_B, "tc_node_b");
    ASSERT_EQ(ret, 0);

    ret = egl_reconfig_commit(g);
    ASSERT_EQ(ret, 0);

    /* Both nodes should be loaded — adding to occupied slot fails */
    ret = egl_graph_add_node(g, 0, NODE_C, "tc_node_c");
    ASSERT_EQ(ret, -EEXIST);

    /* Verify map fds are valid */
    ASSERT_GE(egl_graph_get_prog_array_fd(g), 0);
    ASSERT_GE(egl_graph_get_stats_fd(g), 0);

    egl_graph_destroy(g);
    PASS();
}

/* ================================================================
 * Stats: read, read_all, reset with real BPF maps
 * ================================================================ */

static void test_stats_read_loaded(void)
{
    struct egl_graph *g;
    struct egl_node_stats stats;
    int ret;

    TEST("stats_read_loaded");
    REQUIRE_BPF();

    g = egl_graph_create("stats_read", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    ret = egl_graph_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);

    /* Read stats — should succeed now that maps exist */
    ret = egl_stats_read(g, 0, &stats);
    ASSERT_EQ(ret, 0);

    /* No packets processed, counters should be zero */
    if (stats.in_count != 0 || stats.out_count != 0) {
        FAIL("expected zero counters on fresh node");
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_stats_read_all_loaded(void)
{
    struct egl_graph *g;
    struct egl_node_stats stats[8];
    int ret;

    TEST("stats_read_all_loaded");
    REQUIRE_BPF();

    g = egl_graph_create("stats_all", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    ret = egl_graph_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);

    ret = egl_stats_read_all(g, stats, 8);
    ASSERT_EQ(ret, 0);

    /* All counters should be zero */
    if (stats[0].in_count != 0) {
        FAIL("expected zero counters");
    }

    egl_graph_destroy(g);
    PASS();
}

static void test_stats_reset_loaded(void)
{
    struct egl_graph *g;
    struct egl_node_stats stats;
    int ret;

    TEST("stats_reset_loaded");
    REQUIRE_BPF();

    g = egl_graph_create("stats_reset", 8);
    if (g == NULL) { FAIL("graph create failed"); }

    ret = egl_graph_add_node(g, 0, NODE_A, "tc_node_a");
    ASSERT_EQ(ret, 0);

    /* Reset node 0 stats */
    ret = egl_stats_reset(g, 0);
    ASSERT_EQ(ret, 0);

    /* Read back — should still be zero */
    ret = egl_stats_read(g, 0, &stats);
    ASSERT_EQ(ret, 0);

    if (stats.in_count != 0 || stats.drops != 0 || stats.errors != 0) {
        FAIL("expected zero after reset");
    }

    egl_graph_destroy(g);
    PASS();
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void)
{
    printf("=== TC Pipeline Integration Tests ===\n\n");

    printf("--- Graph ---\n");
    test_tc_pipeline_dag();
    test_tc_pipeline_cycle_detection();
    test_tc_pipeline_full();
    test_graph_add_node_duplicate();
    test_graph_add_node_bad_prog_name();
    test_graph_add_node_bad_file();

    printf("\n--- Loader ---\n");
    test_loader_open_close();
    test_loader_null_path();
    test_loader_bad_path();
    test_loader_get_prog_fd();
    test_loader_get_prog_type();
    test_loader_pin_reuse_maps();
    test_loader_close_null();

    printf("\n--- Reconfig ---\n");
    test_reconfig_null_args();
    test_reconfig_not_active();
    test_reconfig_begin_abort();
    test_reconfig_double_begin();
    test_reconfig_wrong_graph();
    test_reconfig_commit_removes();
    test_reconfig_commit_adds();

    printf("\n--- Stats ---\n");
    test_stats_read_loaded();
    test_stats_read_all_loaded();
    test_stats_reset_loaded();

    printf("\n--- Results: %d/%d passed, %d skipped, %d failed ---\n",
           tests_passed, tests_run, tests_skipped, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
