/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_NODE_H
#define EGL_NODE_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "egl_types.h"

/*
 * Tail-call to the next node in the graph.
 * Works identically for XDP, TC, and other program types.
 */
#define EGL_NEXT(ctx, prog_array, node_id) \
    bpf_tail_call(ctx, &(prog_array), node_id)

/*
 * Defense-in-depth: runtime tail-call depth tracking.
 *
 * The kernel enforces MAX_TAIL_CALL_CNT (33) as a hard limit, but
 * this macro provides an application-level limit that fires earlier,
 * giving nodes the opportunity to handle excessive depth gracefully
 * (e.g., log, increment error counter) rather than silently failing.
 *
 * Usage:
 *
 *   EGL_DECLARE_DEPTH_MAP(egl_depth);
 *
 *   SEC("tc")
 *   int my_node(struct __sk_buff *skb) {
 *       if (EGL_DEPTH_EXCEEDED(egl_depth, 30)) {
 *           EGL_STATS_INC_DROP(egl_node_stats, MY_NODE_ID);
 *           return 0;  // program-type-specific default action
 *       }
 *       // ... node logic ...
 *       EGL_NEXT(skb, egl_prog_array, next_node);
 *       return 0;
 *   }
 *
 * The depth map is a PERCPU_ARRAY with a single entry (index 0).
 * Each node increments it before tail-calling. The entry node must
 * reset it to 0 at the start of each packet/invocation.
 *
 * This is OPTIONAL — nodes that don't use it still benefit from
 * the kernel's hard limit at depth 33.
 */

/* Declare the per-CPU depth counter map (single entry). */
#define EGL_DECLARE_DEPTH_MAP(name)                                     \
    struct {                                                            \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                        \
        __uint(max_entries, 1);                                         \
        __type(key, __u32);                                             \
        __type(value, __u32);                                           \
    } name SEC(".maps")

/* Reset depth counter to 0. Call at the entry node of each pipeline. */
#define EGL_DEPTH_RESET(depth_map)                                      \
    do {                                                                \
        __u32 _dk = 0;                                                  \
        __u32 *_dv = bpf_map_lookup_elem(&(depth_map), &_dk);          \
        if (_dv)                                                        \
            *_dv = 0;                                                   \
    } while (0)

/*
 * Check if depth exceeds the given limit and increment the counter.
 * Returns 1 (true) if depth is exceeded, 0 if safe to continue.
 */
#define EGL_DEPTH_EXCEEDED(depth_map, max_depth)                        \
    ({                                                                  \
        __u32 _dk = 0;                                                  \
        __u32 *_dv = bpf_map_lookup_elem(&(depth_map), &_dk);          \
        int _exceeded = 1;                                              \
        if (_dv) {                                                      \
            if (*_dv < (__u32)(max_depth)) {                            \
                (*_dv)++;                                               \
                _exceeded = 0;                                          \
            }                                                           \
        }                                                               \
        _exceeded;                                                      \
    })

#endif /* EGL_NODE_H */
