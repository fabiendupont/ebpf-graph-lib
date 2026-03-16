/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_RECONFIG_H
#define EGL_RECONFIG_H

/*
 * Staged graph reconfiguration.
 *
 * Thread safety: NOT thread-safe. Each egl_graph instance has its
 * own staging area — different graphs may have independent active
 * reconfigurations. However, concurrent calls to egl_reconfig_*
 * functions on the SAME graph from different threads will corrupt
 * state.
 *
 * Callers MUST serialize all reconfiguration operations on a given
 * graph externally (e.g., mutex, single-threaded control plane).
 *
 * egl_reconfig_begin() returns -EBUSY if a transaction is already
 * active on the given graph, but this check is NOT atomic and does
 * NOT provide thread safety — it only catches sequential misuse.
 */

struct egl_graph;

int egl_reconfig_begin(struct egl_graph *g);
int egl_reconfig_add_node(struct egl_graph *g, int index,
                          const char *bpf_obj_path, const char *prog_name);
int egl_reconfig_remove_node(struct egl_graph *g, int index);
int egl_reconfig_commit(struct egl_graph *g);
int egl_reconfig_abort(struct egl_graph *g);

#endif /* EGL_RECONFIG_H */
