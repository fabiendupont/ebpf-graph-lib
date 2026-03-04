/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_TYPES_H
#define EGL_TYPES_H

#include <linux/types.h>

/*
 * Default maximum number of nodes in a graph.
 * Can be overridden per-graph via egl_graph_create().
 * The PROG_ARRAY is sparse -- unused entries cost ~8 bytes each.
 * 256 entries = 2KB, which is negligible.
 */
#define EGL_DEFAULT_MAX_NODES  256

/* Per-node counter structure stored in PERCPU_ARRAY.
 * Field names are generic -- downstream libraries map them
 * to domain-specific meanings (e.g., xdp-graph-lib maps
 * in_count to received packets, out_count to forwarded packets). */
struct egl_node_stats {
    __u64 in_count;     /* invocations / items received */
    __u64 in_bytes;     /* input volume */
    __u64 out_count;    /* items forwarded to next node */
    __u64 out_bytes;    /* output volume */
    __u64 drops;        /* intentionally discarded */
    __u64 errors;       /* processing failures */
};

#endif /* EGL_TYPES_H */
