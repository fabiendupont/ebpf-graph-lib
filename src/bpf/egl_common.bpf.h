/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_COMMON_BPF_H
#define EGL_COMMON_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <egl/egl_types.h>
#include <egl/egl_edge.h>
#include <egl/egl_stats.h>
#include <egl/egl_node.h>

/* Default shared maps -- nodes include this header to get
 * the prog_array and stats maps. */
EGL_DECLARE_PROG_ARRAY(egl_prog_array);
EGL_DECLARE_STATS(egl_node_stats);

#endif /* EGL_COMMON_BPF_H */
