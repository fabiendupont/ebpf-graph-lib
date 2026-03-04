/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Unit tests for DAG validation (cycle detection).
 * Tests the egl_graph_validate_dag() function using Kahn's algorithm.
 */

#include <egl/egl_graph.h>
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

/* Empty graph: no edges, should be valid */
static void test_dag_empty(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_empty");

    g = egl_graph_create("test_empty", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* Linear chain: A(0) -> B(1) -> C(2), valid DAG */
static void test_dag_linear_chain(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_linear_chain");

    g = egl_graph_create("test_linear", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge(g, 0, 1);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 1, 2);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* Diamond: A->B, A->C, B->D, C->D — valid DAG */
static void test_dag_diamond(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_diamond");

    g = egl_graph_create("test_diamond", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge(g, 0, 1);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 0, 2);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 1, 3);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 2, 3);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* Simple cycle: A(0) -> B(1) -> A(0), should return -ELOOP */
static void test_dag_simple_cycle(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_simple_cycle");

    g = egl_graph_create("test_cycle", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge(g, 0, 1);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 1, 0);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, -ELOOP);

    egl_graph_destroy(g);
    PASS();
}

/* Self-loop: A(0) -> A(0), should return -ELOOP */
static void test_dag_self_loop(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_self_loop");

    g = egl_graph_create("test_self_loop", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge(g, 0, 0);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, -ELOOP);

    egl_graph_destroy(g);
    PASS();
}

/* Complex cycle in larger graph: 0->1->2->3->1 */
static void test_dag_complex_cycle(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_complex_cycle");

    g = egl_graph_create("test_complex", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge(g, 0, 1);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 1, 2);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 2, 3);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 3, 1);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, -ELOOP);

    egl_graph_destroy(g);
    PASS();
}

/* Edge with invalid indices */
static void test_dag_invalid_edge(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_invalid_edge");

    g = egl_graph_create("test_invalid", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge(g, -1, 0);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_add_edge(g, 0, 8);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Remove edge removes cycle */
static void test_dag_remove_edge(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_remove_edge");

    g = egl_graph_create("test_remove", 8);
    if (g == NULL) { FAIL("create failed"); }

    /* Create cycle: 0->1->0 */
    ret = egl_graph_add_edge(g, 0, 1);
    ASSERT_EQ(ret, 0);
    ret = egl_graph_add_edge(g, 1, 0);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, -ELOOP);

    /* Remove back-edge, should be valid now */
    ret = egl_graph_remove_edge(g, 1, 0);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* Configurable graph size: max_nodes=64 */
static void test_dag_configurable_size(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_configurable_size");

    g = egl_graph_create("test_size64", 64);
    if (g == NULL) { FAIL("create failed"); }

    /* Add edge at high indices */
    ret = egl_graph_add_edge(g, 60, 63);
    ASSERT_EQ(ret, 0);

    /* Index out of range */
    ret = egl_graph_add_edge(g, 64, 0);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* Default max_nodes when 0 is passed */
static void test_dag_default_size(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_default_size");

    g = egl_graph_create("test_default", 0);
    if (g == NULL) { FAIL("create failed"); }

    /* Should accept indices up to 255 (EGL_DEFAULT_MAX_NODES=256) */
    ret = egl_graph_add_edge(g, 0, 255);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_add_edge(g, 256, 0);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* NULL graph to edge functions */
static void test_dag_null_graph_edges(void)
{
    int ret;

    TEST("dag_null_graph_edges");

    ret = egl_graph_add_edge(NULL, 0, 1);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_remove_edge(NULL, 0, 1);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

/* Remove edge with various invalid indices */
static void test_dag_remove_edge_invalid(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_remove_edge_invalid");

    g = egl_graph_create("test_re_inv", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_remove_edge(g, -1, 0);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_remove_edge(g, 8, 0);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_remove_edge(g, 0, -1);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_remove_edge(g, 0, 8);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Add edge with negative 'to' index */
static void test_dag_add_edge_negative_to(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_add_edge_negative_to");

    g = egl_graph_create("test_neg_to", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge(g, 0, -1);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Destroy NULL graph (should not crash) */
static void test_dag_destroy_null(void)
{
    TEST("dag_destroy_null");

    egl_graph_destroy(NULL);

    PASS();
}

/* Remove node from NULL graph */
static void test_dag_remove_node_null(void)
{
    TEST("dag_remove_node_null");

    ASSERT_EQ(egl_graph_remove_node(NULL, 0), -EINVAL);

    PASS();
}

/* add_edge_safe: accepts valid DAG edge */
static void test_dag_add_edge_safe_valid(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_add_edge_safe_valid");

    g = egl_graph_create("test_safe_ok", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge_safe(g, 0, 1);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_add_edge_safe(g, 1, 2);
    ASSERT_EQ(ret, 0);

    /* Verify DAG is still valid */
    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* add_edge_safe: rejects edge that would create cycle */
static void test_dag_add_edge_safe_cycle(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_add_edge_safe_cycle");

    g = egl_graph_create("test_safe_cyc", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge_safe(g, 0, 1);
    ASSERT_EQ(ret, 0);

    ret = egl_graph_add_edge_safe(g, 1, 2);
    ASSERT_EQ(ret, 0);

    /* This would create cycle: 2->0 */
    ret = egl_graph_add_edge_safe(g, 2, 0);
    ASSERT_EQ(ret, -ELOOP);

    /* DAG should still be valid (edge was rolled back) */
    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* add_edge_safe: rejects self-loop */
static void test_dag_add_edge_safe_self_loop(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_add_edge_safe_self_loop");

    g = egl_graph_create("test_safe_self", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge_safe(g, 0, 0);
    ASSERT_EQ(ret, -ELOOP);

    /* Graph should be clean */
    ret = egl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    egl_graph_destroy(g);
    PASS();
}

/* add_edge_safe: invalid args */
static void test_dag_add_edge_safe_invalid(void)
{
    struct egl_graph *g;
    int ret;

    TEST("dag_add_edge_safe_invalid");

    g = egl_graph_create("test_safe_inv", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_graph_add_edge_safe(g, -1, 0);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_graph_add_edge_safe(NULL, 0, 1);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

int main(void)
{
    printf("=== DAG Validation Tests ===\n");

    test_dag_empty();
    test_dag_linear_chain();
    test_dag_diamond();
    test_dag_simple_cycle();
    test_dag_self_loop();
    test_dag_complex_cycle();
    test_dag_invalid_edge();
    test_dag_remove_edge();
    test_dag_configurable_size();
    test_dag_default_size();
    test_dag_null_graph_edges();
    test_dag_remove_edge_invalid();
    test_dag_add_edge_negative_to();
    test_dag_destroy_null();
    test_dag_remove_node_null();
    test_dag_add_edge_safe_valid();
    test_dag_add_edge_safe_cycle();
    test_dag_add_edge_safe_self_loop();
    test_dag_add_edge_safe_invalid();

    printf("\n--- Results: %d/%d passed, %d failed ---\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
