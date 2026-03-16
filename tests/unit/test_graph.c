/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Unit tests for graph lifecycle management.
 * Tests egl_graph_create/destroy, add/remove node, error cases.
 *
 * Note: Tests that require BPF object loading (add_node, remove_node
 * with actual BPF programs) need root privileges and kernel support.
 * Tests here focus on the userspace data structure management.
 */

#include <egl/egl_graph.h>
#include <egl/egl_reconfig.h>
#include <egl/egl_types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

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

#define ASSERT_EQ(a, b) \
    do { \
        int _a = (a); \
        int _b = (b); \
        if (_a != _b) { \
            printf("FAIL: %s == %s (%d != %d)\n", #a, #b, _a, _b); \
            tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_NOT_NULL(p) \
    do { \
        if ((p) == NULL) { \
            printf("FAIL: %s != NULL\n", #p); \
            tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_NULL(p) \
    do { \
        if ((p) != NULL) { \
            printf("FAIL: %s == NULL\n", #p); \
            tests_failed++; \
            return; \
        } \
    } while (0)

/* Create and destroy without adding nodes */
static void test_graph_create_destroy(void)
{
    struct egl_graph *g;

    TEST("graph_create_destroy");

    g = egl_graph_create("test_basic", 16);
    ASSERT_NOT_NULL(g);

    egl_graph_destroy(g);
    PASS();
}

/* Create with default max_nodes (pass 0) */
static void test_graph_default_max_nodes(void)
{
    struct egl_graph *g;

    TEST("graph_default_max_nodes");

    g = egl_graph_create("test_default", 0);
    ASSERT_NOT_NULL(g);

    /* Verify by attempting edge at index 255 (should work with 256 nodes) */
    ASSERT_EQ(egl_graph_add_edge(g, 0, 255), 0);
    ASSERT_EQ(egl_graph_add_edge(g, 256, 0), -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Create with specific max_nodes */
static void test_graph_custom_max_nodes(void)
{
    struct egl_graph *g;

    TEST("graph_custom_max_nodes");

    g = egl_graph_create("test_custom", 64);
    ASSERT_NOT_NULL(g);

    ASSERT_EQ(egl_graph_add_edge(g, 0, 63), 0);
    ASSERT_EQ(egl_graph_add_edge(g, 64, 0), -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* NULL name should fail */
static void test_graph_null_name(void)
{
    struct egl_graph *g;

    TEST("graph_null_name");

    g = egl_graph_create(NULL, 16);
    ASSERT_NULL(g);

    PASS();
}

/* Invalid index for add_node */
static void test_graph_add_node_invalid_index(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_add_node_invalid_index");

    g = egl_graph_create("test_invalid", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_graph_add_node(g, -1, "/nonexistent.o", "prog");
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_add_node(g, 8, "/nonexistent.o", "prog");
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* NULL arguments to add_node */
static void test_graph_add_node_null_args(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_add_node_null_args");

    g = egl_graph_create("test_null", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_graph_add_node(g, 0, NULL, "prog");
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_add_node(g, 0, "/test.o", NULL);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_add_node(NULL, 0, "/test.o", "prog");
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Remove non-existent node */
static void test_graph_remove_nonexistent(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_remove_nonexistent");

    g = egl_graph_create("test_remove", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_graph_remove_node(g, 0);
    ASSERT_EQ(ret, -ENOENT);

    egl_graph_destroy(g);
    PASS();
}

/* Remove with invalid index */
static void test_graph_remove_invalid_index(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_remove_invalid_index");

    g = egl_graph_create("test_remove_inv", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_graph_remove_node(g, -1);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_remove_node(g, 8);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Map fd accessors return -1 before maps are created */
static void test_graph_map_fds_initial(void)
{
    struct egl_graph *g;

    TEST("graph_map_fds_initial");

    g = egl_graph_create("test_fds", 8);
    ASSERT_NOT_NULL(g);

    /* Before any node is added, fds should be -1 */
    ASSERT_EQ(egl_graph_get_prog_array_fd(g), -1);
    ASSERT_EQ(egl_graph_get_stats_fd(g), -1);

    egl_graph_destroy(g);
    PASS();
}

/* NULL graph to accessors */
static void test_graph_null_accessors(void)
{
    TEST("graph_null_accessors");

    ASSERT_EQ(egl_graph_get_prog_array_fd(NULL), -EINVAL);
    ASSERT_EQ(egl_graph_get_stats_fd(NULL), -EINVAL);
    ASSERT_EQ(egl_graph_validate_dag(NULL), -EINVAL);

    PASS();
}

/* Reconfig: add_node with NULL sub-args */
static void test_reconfig_add_null_args(void)
{
    struct egl_graph *g;
    int ret;

    TEST("reconfig_add_null_args");

    g = egl_graph_create("test_rc_null", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    /* NULL bpf_obj_path */
    ret = egl_reconfig_add_node(g, 0, NULL, "prog");
    ASSERT_EQ(ret, -EINVAL);

    /* NULL prog_name */
    ret = egl_reconfig_add_node(g, 0, "path.o", NULL);
    ASSERT_EQ(ret, -EINVAL);

    (void)egl_reconfig_abort(g);
    egl_graph_destroy(g);
    PASS();
}

/* Reconfig: overflow EGL_MAX_STAGED adds */
static void test_reconfig_add_overflow(void)
{
    struct egl_graph *g;
    int ret;
    int i;

    TEST("reconfig_add_overflow");

    g = egl_graph_create("test_rc_ovfl", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    /* Stage 64 adds (EGL_MAX_STAGED) */
    for (i = 0; i < 64; i++) {
        ret = egl_reconfig_add_node(g, 0, "dummy.o", "prog");
        ASSERT_EQ(ret, 0);
    }

    /* 65th should fail with -ENOSPC */
    ret = egl_reconfig_add_node(g, 0, "dummy.o", "prog");
    ASSERT_EQ(ret, -ENOSPC);

    (void)egl_reconfig_abort(g);
    egl_graph_destroy(g);
    PASS();
}

/* Reconfig: overflow EGL_MAX_STAGED removes */
static void test_reconfig_remove_overflow(void)
{
    struct egl_graph *g;
    int ret;
    int i;

    TEST("reconfig_remove_overflow");

    g = egl_graph_create("test_rc_rmovfl", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_reconfig_begin(g);
    ASSERT_EQ(ret, 0);

    for (i = 0; i < 64; i++) {
        ret = egl_reconfig_remove_node(g, 0);
        ASSERT_EQ(ret, 0);
    }

    /* 65th should fail */
    ret = egl_reconfig_remove_node(g, 0);
    ASSERT_EQ(ret, -ENOSPC);

    (void)egl_reconfig_abort(g);
    egl_graph_destroy(g);
    PASS();
}

/* alloc_index: sequential allocation */
static void test_graph_alloc_index_sequential(void)
{
    struct egl_graph *g;
    int idx;

    TEST("graph_alloc_index_sequential");

    g = egl_graph_create("test_alloc_seq", 4);
    ASSERT_NOT_NULL(g);

    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, 0);
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, 1);
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, 2);
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, 3);

    /* All slots taken */
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, -ENOSPC);

    egl_graph_destroy(g);
    PASS();
}

/* alloc_index: NULL graph */
static void test_graph_alloc_index_null(void)
{
    TEST("graph_alloc_index_null");

    ASSERT_EQ(egl_graph_alloc_index(NULL), -EINVAL);

    PASS();
}

/* reserve_index: reserve specific slot */
static void test_graph_reserve_index(void)
{
    struct egl_graph *g;
    int ret;

    TEST("graph_reserve_index");

    g = egl_graph_create("test_reserve", 8);
    ASSERT_NOT_NULL(g);

    ret = egl_graph_reserve_index(g, 5);
    ASSERT_EQ(ret, 0);

    /* Double reserve should fail */
    ret = egl_graph_reserve_index(g, 5);
    ASSERT_EQ(ret, -EEXIST);

    egl_graph_destroy(g);
    PASS();
}

/* reserve_index: invalid args */
static void test_graph_reserve_index_invalid(void)
{
    struct egl_graph *g;

    TEST("graph_reserve_index_invalid");

    g = egl_graph_create("test_res_inv", 8);
    ASSERT_NOT_NULL(g);

    ASSERT_EQ(egl_graph_reserve_index(NULL, 0), -EINVAL);
    ASSERT_EQ(egl_graph_reserve_index(g, -1), -EINVAL);
    ASSERT_EQ(egl_graph_reserve_index(g, 8), -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* alloc skips reserved indices */
static void test_graph_alloc_skips_reserved(void)
{
    struct egl_graph *g;
    int idx;

    TEST("graph_alloc_skips_reserved");

    g = egl_graph_create("test_alloc_skip", 4);
    ASSERT_NOT_NULL(g);

    /* Reserve slots 0 and 2 */
    ASSERT_EQ(egl_graph_reserve_index(g, 0), 0);
    ASSERT_EQ(egl_graph_reserve_index(g, 2), 0);

    /* alloc should return 1, then 3 */
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, 1);
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, 3);

    /* All full now */
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, -ENOSPC);

    egl_graph_destroy(g);
    PASS();
}

/* free_index: release and re-allocate */
static void test_graph_free_index(void)
{
    struct egl_graph *g;
    int idx;

    TEST("graph_free_index");

    g = egl_graph_create("test_free", 4);
    ASSERT_NOT_NULL(g);

    /* Allocate all */
    ASSERT_EQ(egl_graph_alloc_index(g), 0);
    ASSERT_EQ(egl_graph_alloc_index(g), 1);
    ASSERT_EQ(egl_graph_alloc_index(g), 2);
    ASSERT_EQ(egl_graph_alloc_index(g), 3);
    ASSERT_EQ(egl_graph_alloc_index(g), -ENOSPC);

    /* Free index 1 */
    ASSERT_EQ(egl_graph_free_index(g, 1), 0);

    /* Alloc should return 1 again */
    idx = egl_graph_alloc_index(g);
    ASSERT_EQ(idx, 1);

    egl_graph_destroy(g);
    PASS();
}

/* free_index: error cases */
static void test_graph_free_index_errors(void)
{
    struct egl_graph *g;

    TEST("graph_free_index_errors");

    g = egl_graph_create("test_free_err", 8);
    ASSERT_NOT_NULL(g);

    /* Free unreserved index */
    ASSERT_EQ(egl_graph_free_index(g, 0), -ENOENT);

    /* Invalid args */
    ASSERT_EQ(egl_graph_free_index(NULL, 0), -EINVAL);
    ASSERT_EQ(egl_graph_free_index(g, -1), -EINVAL);
    ASSERT_EQ(egl_graph_free_index(g, 8), -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* get_max_nodes accessor */
static void test_graph_get_max_nodes(void)
{
    struct egl_graph *g;

    TEST("graph_get_max_nodes");

    g = egl_graph_create("test_mn", 42);
    ASSERT_NOT_NULL(g);

    ASSERT_EQ(egl_graph_get_max_nodes(g), 42);
    ASSERT_EQ(egl_graph_get_max_nodes(NULL), -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* get_max_nodes with default */
static void test_graph_get_max_nodes_default(void)
{
    struct egl_graph *g;

    TEST("graph_get_max_nodes_default");

    g = egl_graph_create("test_mn_def", 0);
    ASSERT_NOT_NULL(g);

    ASSERT_EQ(egl_graph_get_max_nodes(g), 256);

    egl_graph_destroy(g);
    PASS();
}

/* Per-graph reconfig: two graphs can have independent reconfigs */
static void test_reconfig_per_graph(void)
{
    struct egl_graph *g1;
    struct egl_graph *g2;
    int ret;

    TEST("reconfig_per_graph");

    g1 = egl_graph_create("test_rc1", 8);
    ASSERT_NOT_NULL(g1);

    g2 = egl_graph_create("test_rc2", 8);
    ASSERT_NOT_NULL(g2);

    /* Begin reconfig on g1 */
    ret = egl_reconfig_begin(g1);
    ASSERT_EQ(ret, 0);

    /* Begin reconfig on g2 should also succeed (no longer global) */
    ret = egl_reconfig_begin(g2);
    ASSERT_EQ(ret, 0);

    /* Double begin on g1 should fail */
    ret = egl_reconfig_begin(g1);
    ASSERT_EQ(ret, -EBUSY);

    (void)egl_reconfig_abort(g1);
    (void)egl_reconfig_abort(g2);
    egl_graph_destroy(g1);
    egl_graph_destroy(g2);
    PASS();
}

int main(void)
{
    printf("=== Graph Lifecycle Tests ===\n");

    test_graph_create_destroy();
    test_graph_default_max_nodes();
    test_graph_custom_max_nodes();
    test_graph_null_name();
    test_graph_add_node_invalid_index();
    test_graph_add_node_null_args();
    test_graph_remove_nonexistent();
    test_graph_remove_invalid_index();
    test_graph_map_fds_initial();
    test_graph_null_accessors();
    test_reconfig_add_null_args();
    test_reconfig_add_overflow();
    test_reconfig_remove_overflow();
    test_graph_alloc_index_sequential();
    test_graph_alloc_index_null();
    test_graph_reserve_index();
    test_graph_reserve_index_invalid();
    test_graph_alloc_skips_reserved();
    test_graph_free_index();
    test_graph_free_index_errors();
    test_graph_get_max_nodes();
    test_graph_get_max_nodes_default();
    test_reconfig_per_graph();

    printf("\n--- Results: %d/%d passed, %d failed ---\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
