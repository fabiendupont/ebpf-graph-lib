/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_RECONFIG_H
#define EGL_RECONFIG_H

/*
 * Staged graph reconfiguration.
 *
 * Thread safety: NOT thread-safe. The reconfiguration API uses a
 * global staging area — only one reconfiguration transaction can be
 * active at a time across ALL graphs. Concurrent calls to any
 * egl_reconfig_* function from different threads will corrupt state.
 *
 * Callers MUST serialize all reconfiguration operations externally
 * (e.g., mutex, single-threaded control plane).
 *
 * egl_reconfig_begin() returns -EBUSY if a transaction is already
 * active, but this check is NOT atomic and does NOT provide thread
 * safety — it only catches sequential misuse.
 */

struct egl_graph;

int egl_reconfig_begin(struct egl_graph *g);
int egl_reconfig_add_node(struct egl_graph *g, int index,
                          const char *bpf_obj_path, const char *prog_name);
int egl_reconfig_remove_node(struct egl_graph *g, int index);
int egl_reconfig_commit(struct egl_graph *g);
int egl_reconfig_abort(struct egl_graph *g);

#endif /* EGL_RECONFIG_H */
