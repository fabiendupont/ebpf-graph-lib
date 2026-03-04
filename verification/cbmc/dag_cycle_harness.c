/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * CBMC verification harness for DAG cycle detection.
 *
 * Proves that egl_graph_validate_dag() correctly identifies:
 * - ALL cyclic graphs up to HARNESS_MAX_NODES nodes -> returns -ELOOP
 * - ALL acyclic graphs up to HARNESS_MAX_NODES nodes -> returns 0
 *
 * The proof uses a DFS oracle as a reference implementation and
 * exhaustively checks all possible edge combinations.
 *
 * Run:
 *   cbmc dag_cycle_harness.c ../../src/userspace/egl_graph.c \
 *     -I ../../include --unwind 5 --bounds-check --pointer-check \
 *     --signed-overflow-check -DHARNESS_MAX_NODES=3 --object-bits 12
 */

#define _POSIX_C_SOURCE 200809L

#include <egl/egl_graph.h>
#include <egl/egl_types.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARNESS_MAX_NODES
#define HARNESS_MAX_NODES 3
#endif

/*
 * Stubs for system/BPF functions used by egl_graph.c.
 * These are not relevant to DAG correctness.
 */
int bpf_map_create(int map_type, const char *name,
                   unsigned int key_size, unsigned int value_size,
                   unsigned int max_entries, const void *opts)
{
    (void)map_type; (void)name; (void)key_size;
    (void)value_size; (void)max_entries; (void)opts;
    return 3;
}

int bpf_obj_pin(int fd, const char *path)
{
    (void)fd; (void)path;
    return 0;
}

int bpf_map_delete_elem(int fd, const void *key)
{
    (void)fd; (void)key;
    return 0;
}

int bpf_map_update_elem(int fd, const void *key, const void *value,
                        unsigned long long flags)
{
    (void)fd; (void)key; (void)value; (void)flags;
    return 0;
}

int mkdir(const char *path, unsigned int mode)
{
    (void)path; (void)mode;
    return 0;
}

int rmdir(const char *path)
{
    (void)path;
    return 0;
}

int unlink(const char *path)
{
    (void)path;
    return 0;
}

/*
 * DFS-based cycle detection as an oracle (reference implementation).
 * Returns 1 if a cycle exists, 0 if acyclic.
 */
static int dfs_has_cycle(unsigned char *edges, int n, int node,
                         int *visited, int *rec_stack)
{
    visited[node] = 1;
    rec_stack[node] = 1;

    for (int j = 0; j < n; j++) {
        if (edges[node * n + j] == 0) { continue; }
        if (!visited[j]) {
            if (dfs_has_cycle(edges, n, j, visited, rec_stack)) {
                return 1;
            }
        } else if (rec_stack[j]) {
            return 1;
        }
    }

    rec_stack[node] = 0;
    return 0;
}

static int oracle_has_cycle(unsigned char *edges, int n)
{
    int visited[HARNESS_MAX_NODES] = {0};
    int rec_stack[HARNESS_MAX_NODES] = {0};

    for (int i = 0; i < n; i++) {
        if (!visited[i]) {
            if (dfs_has_cycle(edges, n, i, visited, rec_stack)) {
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Main CBMC harness.
 *
 * Constructs a graph, populates non-deterministic edges, and verifies
 * that Kahn's algorithm agrees with the DFS oracle on cycle detection.
 */
int main(void)
{
    int n = HARNESS_MAX_NODES;
    struct egl_graph *g;
    unsigned char oracle_edges[HARNESS_MAX_NODES * HARNESS_MAX_NODES];
    int ret;

    (void)memset(oracle_edges, 0, sizeof(oracle_edges));

    g = egl_graph_create("t", n);
    __CPROVER_assume(g != NULL);

    /* Non-deterministically populate edges in both representations */
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            _Bool has_edge;
            oracle_edges[i * n + j] = has_edge ? 1 : 0;
            if (has_edge) {
                int r = egl_graph_add_edge(g, i, j);
                __CPROVER_assume(r == 0);
            }
        }
    }

    /* Run Kahn's algorithm (implementation under test) */
    ret = egl_graph_validate_dag(g);

    /* Skip allocation-failure paths (not what we're proving) */
    __CPROVER_assume(ret == 0 || ret == -ELOOP);

    /* Run DFS oracle */
    int has_cycle = oracle_has_cycle(oracle_edges, n);

    /* Core safety property: implementations must agree */
    if (has_cycle) {
        assert(ret == -ELOOP);
    } else {
        assert(ret == 0);
    }

    egl_graph_destroy(g);
    return 0;
}
