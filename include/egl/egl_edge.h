/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_EDGE_H
#define EGL_EDGE_H

#include "egl_types.h"

/*
 * Declare the PROG_ARRAY map for tail calls.
 *
 * max_entries is set to EGL_DEFAULT_MAX_NODES here as a compile-time
 * placeholder. The actual size is overridden at load time by
 * egl_loader via bpf_map__set_max_entries() using the value passed
 * to egl_graph_create().
 */
#define EGL_DECLARE_PROG_ARRAY(name)                        \
    struct {                                                \
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);              \
        __uint(max_entries, EGL_DEFAULT_MAX_NODES);         \
        __type(key, __u32);                                 \
        __type(value, __u32);                               \
    } name SEC(".maps")

#endif /* EGL_EDGE_H */
