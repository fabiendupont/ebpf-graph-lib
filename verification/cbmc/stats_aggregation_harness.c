/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * CBMC verification harness for stats aggregation correctness.
 *
 * Proves that egl_stats_read correctly sums PERCPU_ARRAY values
 * across all CPUs. The harness stubs bpf_map_lookup_elem to return
 * a non-deterministic per-CPU array and verifies the aggregation
 * matches a direct summation.
 *
 * Run:
 *   cbmc stats_aggregation_harness.c ../../src/userspace/egl_stats.c \
 *     -I ../../include -D_POSIX_C_SOURCE=200809L \
 *     --unwind 10 --bounds-check --pointer-check \
 *     --signed-overflow-check --object-bits 12 \
 *     --drop-unused-functions
 */

#define _POSIX_C_SOURCE 200809L

#include <egl/egl_stats.h>
#include <egl/egl_types.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARNESS_NUM_CPUS
#define HARNESS_NUM_CPUS 4
#endif

/* Non-deterministic per-CPU stats that the stub will return */
static struct egl_node_stats stub_percpu[HARNESS_NUM_CPUS];
static int stub_prepared = 0;

/* Stub: return a fake stats_fd */
struct egl_graph;
int egl_graph_get_stats_fd(const struct egl_graph *g)
{
    (void)g;
    return 5; /* fake valid fd */
}

/* Stub: return fixed number of CPUs */
int libbpf_num_possible_cpus(void)
{
    return HARNESS_NUM_CPUS;
}

/* Stub: copy the non-deterministic per-CPU data into the caller's buffer */
int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    (void)fd;
    (void)key;

    if (!stub_prepared) { return -1; }

    (void)memcpy(value, stub_percpu,
                 (size_t)HARNESS_NUM_CPUS * sizeof(struct egl_node_stats));
    return 0;
}

int main(void)
{
    struct egl_node_stats out;
    int ret;
    /* Use a non-NULL pointer as the graph handle.
     * egl_stats_read only uses it via egl_graph_get_stats_fd. */
    int fake_graph = 1;

    /* Populate non-deterministic per-CPU stats */
    for (int i = 0; i < HARNESS_NUM_CPUS; i++) {
        __u64 in_c, in_b, out_c, out_b, drops, errors;
        stub_percpu[i].in_count = in_c;
        stub_percpu[i].in_bytes = in_b;
        stub_percpu[i].out_count = out_c;
        stub_percpu[i].out_bytes = out_b;
        stub_percpu[i].drops = drops;
        stub_percpu[i].errors = errors;
    }
    stub_prepared = 1;

    /* Call the function under test */
    ret = egl_stats_read((void *)&fake_graph, 0, &out);
    /* Skip if internal allocation failed */
    __CPROVER_assume(ret == 0);

    /* Compute expected aggregation */
    __u64 exp_in_count = 0;
    __u64 exp_in_bytes = 0;
    __u64 exp_out_count = 0;
    __u64 exp_out_bytes = 0;
    __u64 exp_drops = 0;
    __u64 exp_errors = 0;

    for (int i = 0; i < HARNESS_NUM_CPUS; i++) {
        exp_in_count += stub_percpu[i].in_count;
        exp_in_bytes += stub_percpu[i].in_bytes;
        exp_out_count += stub_percpu[i].out_count;
        exp_out_bytes += stub_percpu[i].out_bytes;
        exp_drops += stub_percpu[i].drops;
        exp_errors += stub_percpu[i].errors;
    }

    /* Verify aggregation is correct */
    assert(out.in_count == exp_in_count);
    assert(out.in_bytes == exp_in_bytes);
    assert(out.out_count == exp_out_count);
    assert(out.out_bytes == exp_out_bytes);
    assert(out.drops == exp_drops);
    assert(out.errors == exp_errors);

    return 0;
}
