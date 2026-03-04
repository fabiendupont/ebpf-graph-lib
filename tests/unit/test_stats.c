/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Unit tests for stats aggregation.
 * Tests egl_stats_read, egl_stats_read_all, egl_stats_reset.
 *
 * Note: Full stats tests require BPF maps (root/CAP_BPF).
 * These tests verify the API contract and error handling.
 */

#include <egl/egl_graph.h>
#include <egl/egl_stats.h>
#include <egl/egl_types.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

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

/* NULL graph should return error */
static void test_stats_null_graph(void)
{
    struct egl_node_stats out;
    int ret;

    TEST("stats_null_graph");

    ret = egl_stats_read(NULL, 0, &out);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_stats_reset(NULL, 0);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

/* NULL output should return error */
static void test_stats_null_output(void)
{
    struct egl_graph *g;
    int ret;

    TEST("stats_null_output");

    g = egl_graph_create("test_stats", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_stats_read(g, 0, NULL);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Read stats before maps are created (no nodes added) */
static void test_stats_no_maps(void)
{
    struct egl_graph *g;
    struct egl_node_stats out;
    int ret;

    TEST("stats_no_maps");

    g = egl_graph_create("test_no_maps", 8);
    if (g == NULL) { FAIL("create failed"); }

    /* stats_fd is -1 since no maps created yet */
    ret = egl_stats_read(g, 0, &out);
    ASSERT_EQ(ret, -ENOENT);

    egl_graph_destroy(g);
    PASS();
}

/* read_all with invalid args */
static void test_stats_read_all_invalid(void)
{
    struct egl_graph *g;
    struct egl_node_stats out[8];
    int ret;

    TEST("stats_read_all_invalid");

    g = egl_graph_create("test_all_inv", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_stats_read_all(NULL, out, 8);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_stats_read_all(g, NULL, 8);
    ASSERT_EQ(ret, -EINVAL);

    ret = egl_stats_read_all(g, out, 0);
    ASSERT_EQ(ret, -EINVAL);

    egl_graph_destroy(g);
    PASS();
}

/* Reset on graph with no maps (stats_fd < 0) */
static void test_stats_reset_no_maps(void)
{
    struct egl_graph *g;
    int ret;

    TEST("stats_reset_no_maps");

    g = egl_graph_create("test_reset_nomap", 8);
    if (g == NULL) { FAIL("create failed"); }

    ret = egl_stats_reset(g, 0);
    ASSERT_EQ(ret, -ENOENT);

    egl_graph_destroy(g);
    PASS();
}

int main(void)
{
    printf("=== Stats Tests ===\n");

    test_stats_null_graph();
    test_stats_null_output();
    test_stats_no_maps();
    test_stats_read_all_invalid();
    test_stats_reset_no_maps();

    printf("\n--- Results: %d/%d passed, %d failed ---\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
