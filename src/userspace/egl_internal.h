/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_INTERNAL_H
#define EGL_INTERNAL_H

/*
 * Internal API between egl_graph.c and egl_reconfig.c.
 * NOT part of the public interface — do not install this header.
 */

struct egl_graph;

/* Per-graph reconfig state management (implemented in egl_graph.c) */
int egl_reconfig_begin_internal(struct egl_graph *g);
int egl_reconfig_clear_internal(struct egl_graph *g);
int egl_reconfig_stage_add(struct egl_graph *g, int index,
                           const char *bpf_obj_path, const char *prog_name);
int egl_reconfig_stage_remove(struct egl_graph *g, int index);
int egl_reconfig_get_counts(const struct egl_graph *g,
                            int *add_count, int *remove_count);
int egl_reconfig_get_remove_index(const struct egl_graph *g, int i);
void egl_reconfig_get_add_entry(const struct egl_graph *g, int i,
                                int *index, const char **bpf_obj_path,
                                const char **prog_name);

#endif /* EGL_INTERNAL_H */
