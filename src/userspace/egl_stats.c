/* SPDX-License-Identifier: BSD-2-Clause */

#include <egl/egl_stats.h>
#include <egl/egl_types.h>
#include <egl/egl_graph.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Read stats for a single node, aggregating across all CPUs.
 * PERCPU_ARRAY returns one struct egl_node_stats per CPU.
 */
int egl_stats_read(struct egl_graph *g, int node_id,
                   struct egl_node_stats *out)
{
    struct egl_node_stats *percpu_vals;
    int num_cpus;
    int stats_fd;
    __u32 key;
    int ret;

    if (g == NULL || out == NULL) { return -EINVAL; }

    stats_fd = egl_graph_get_stats_fd(g);
    if (stats_fd < 0) { return -ENOENT; }

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) { return num_cpus; }

    percpu_vals = calloc((size_t)num_cpus, sizeof(*percpu_vals));
    if (percpu_vals == NULL) { return -ENOMEM; }

    key = (__u32)node_id;
    ret = bpf_map_lookup_elem(stats_fd, &key, percpu_vals);
    if (ret < 0) {
        free(percpu_vals);
        return -errno;
    }

    /* Aggregate across CPUs */
    (void)memset(out, 0, sizeof(*out));
    for (int i = 0; i < num_cpus; i++) {
        out->in_count += percpu_vals[i].in_count;
        out->in_bytes += percpu_vals[i].in_bytes;
        out->out_count += percpu_vals[i].out_count;
        out->out_bytes += percpu_vals[i].out_bytes;
        out->drops += percpu_vals[i].drops;
        out->errors += percpu_vals[i].errors;
    }

    free(percpu_vals);
    return 0;
}

int egl_stats_read_all(struct egl_graph *g,
                       struct egl_node_stats *out, int max_nodes)
{
    if (g == NULL || out == NULL || max_nodes <= 0) { return -EINVAL; }

    for (int i = 0; i < max_nodes; i++) {
        int ret = egl_stats_read(g, i, &out[i]);
        if (ret < 0) {
            /* Node may not exist; zero its stats */
            (void)memset(&out[i], 0, sizeof(out[i]));
        }
    }

    return 0;
}

int egl_stats_reset(struct egl_graph *g, int node_id)
{
    struct egl_node_stats *percpu_vals;
    int num_cpus;
    int stats_fd;
    __u32 key;
    int ret;

    if (g == NULL) { return -EINVAL; }

    stats_fd = egl_graph_get_stats_fd(g);
    if (stats_fd < 0) { return -ENOENT; }

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) { return num_cpus; }

    percpu_vals = calloc((size_t)num_cpus, sizeof(*percpu_vals));
    if (percpu_vals == NULL) { return -ENOMEM; }

    /* All entries are zeroed by calloc */
    key = (__u32)node_id;
    ret = bpf_map_update_elem(stats_fd, &key, percpu_vals,
                               BPF_ANY);
    if (ret < 0) {
        free(percpu_vals);
        return -errno;
    }

    free(percpu_vals);
    return 0;
}
