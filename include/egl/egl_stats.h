/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_STATS_H
#define EGL_STATS_H

#include "egl_types.h"

#ifdef __BPF__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Declare the per-node stats map.
 * max_entries overridden at load time to match egl_graph_create(). */
#define EGL_DECLARE_STATS(name)                                         \
    struct {                                                            \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                        \
        __uint(max_entries, EGL_DEFAULT_MAX_NODES);                     \
        __type(key, __u32);                                             \
        __type(value, struct egl_node_stats);                           \
    } name SEC(".maps")

#define EGL_STATS_INC_IN(stats_map, node_id, bytes)                     \
    do {                                                                \
        __u32 _k = (node_id);                                           \
        struct egl_node_stats *_s =                                     \
            bpf_map_lookup_elem(&(stats_map), &_k);                     \
        if (_s) {                                                       \
            _s->in_count++;                                             \
            _s->in_bytes += (bytes);                                    \
        }                                                               \
    } while (0)

#define EGL_STATS_INC_OUT(stats_map, node_id, bytes)                    \
    do {                                                                \
        __u32 _k = (node_id);                                           \
        struct egl_node_stats *_s =                                     \
            bpf_map_lookup_elem(&(stats_map), &_k);                     \
        if (_s) {                                                       \
            _s->out_count++;                                            \
            _s->out_bytes += (bytes);                                   \
        }                                                               \
    } while (0)

#define EGL_STATS_INC_DROP(stats_map, node_id)                          \
    do {                                                                \
        __u32 _k = (node_id);                                           \
        struct egl_node_stats *_s =                                     \
            bpf_map_lookup_elem(&(stats_map), &_k);                     \
        if (_s)                                                         \
            _s->drops++;                                                \
    } while (0)

#define EGL_STATS_INC_ERROR(stats_map, node_id)                         \
    do {                                                                \
        __u32 _k = (node_id);                                           \
        struct egl_node_stats *_s =                                     \
            bpf_map_lookup_elem(&(stats_map), &_k);                     \
        if (_s)                                                         \
            _s->errors++;                                               \
    } while (0)

#else /* userspace */

struct egl_graph;

int egl_stats_read(struct egl_graph *g, int node_id,
                   struct egl_node_stats *out);
int egl_stats_read_all(struct egl_graph *g,
                       struct egl_node_stats *out, int max_nodes);
int egl_stats_reset(struct egl_graph *g, int node_id);

#endif /* __BPF__ */

#endif /* EGL_STATS_H */
