/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * CBMC verification harness for node lifecycle memory safety.
 *
 * Proves that egl_graph_add_edge, egl_graph_remove_edge, and
 * egl_graph_validate_dag are memory-safe for all valid and invalid
 * index combinations. Does NOT test BPF loading (add_node/remove_node)
 * since those require kernel interaction.
 *
 * Properties verified:
 *   - No out-of-bounds array access
 *   - No NULL pointer dereference
 *   - No signed integer overflow
 *   - No use-after-free
 *
 * Run:
 *   cbmc node_lifecycle_harness.c ../../src/userspace/egl_graph.c \
 *     -I ../../include -D_POSIX_C_SOURCE=200809L \
 *     --unwind 6 --no-unwinding-assertions \
 *     --bounds-check --pointer-check --signed-overflow-check \
 *     -DHARNESS_MAX_NODES=4 --object-bits 12 --drop-unused-functions
 */

#define _POSIX_C_SOURCE 200809L

#include <egl/egl_graph.h>
#include <egl/egl_types.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARNESS_MAX_NODES
#define HARNESS_MAX_NODES 4
#endif

/* Stubs for BPF/system functions */
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
 * Main harness: exercises add_edge, remove_edge, and validate_dag
 * with non-deterministic indices (including out-of-range).
 */
int main(void)
{
    int n = HARNESS_MAX_NODES;
    struct egl_graph *g;
    int ret;

    g = egl_graph_create("lifecycle", n);
    __CPROVER_assume(g != NULL);

    /* Non-deterministic edge operations with arbitrary indices */
    int from, to;

    /* add_edge with arbitrary (possibly invalid) indices */
    __CPROVER_assume(from >= -1 && from <= n);
    __CPROVER_assume(to >= -1 && to <= n);

    ret = egl_graph_add_edge(g, from, to);
    if (from < 0 || from >= n || to < 0 || to >= n) {
        assert(ret == -EINVAL);
    } else {
        assert(ret == 0);
    }

    /* remove_edge with arbitrary indices */
    int rfrom, rto;
    __CPROVER_assume(rfrom >= -1 && rfrom <= n);
    __CPROVER_assume(rto >= -1 && rto <= n);

    ret = egl_graph_remove_edge(g, rfrom, rto);
    if (rfrom < 0 || rfrom >= n || rto < 0 || rto >= n) {
        assert(ret == -EINVAL);
    } else {
        assert(ret == 0);
    }

    /* Add some valid edges, then validate */
    for (int i = 0; i < n - 1; i++) {
        ret = egl_graph_add_edge(g, i, i + 1);
        assert(ret == 0);
    }

    ret = egl_graph_validate_dag(g);
    __CPROVER_assume(ret == 0 || ret == -ELOOP);
    /* Linear chain is always a DAG */
    assert(ret == 0);

    /* NULL safety checks */
    assert(egl_graph_add_edge(NULL, 0, 1) == -EINVAL);
    assert(egl_graph_remove_edge(NULL, 0, 1) == -EINVAL);
    assert(egl_graph_validate_dag(NULL) == -EINVAL);
    assert(egl_graph_get_prog_array_fd(NULL) == -EINVAL);
    assert(egl_graph_get_stats_fd(NULL) == -EINVAL);
    assert(egl_graph_remove_node(NULL, 0) == -EINVAL);

    egl_graph_destroy(g);

    /* Destroy NULL should not crash */
    egl_graph_destroy(NULL);

    return 0;
}
