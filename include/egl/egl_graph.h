/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_GRAPH_H
#define EGL_GRAPH_H

/*
 * Graph topology management.
 *
 * Thread safety: Individual egl_graph instances are NOT thread-safe.
 * Concurrent calls to egl_graph_* functions on the SAME graph from
 * different threads will corrupt state. Different graphs may be used
 * concurrently from different threads without synchronization.
 *
 * Read-only functions (validate_dag, get_prog_array_fd, get_stats_fd)
 * may be called concurrently with each other on the same graph, but
 * NOT concurrently with mutating functions (add_node, remove_node,
 * add_edge, remove_edge, destroy).
 */

struct egl_graph;

/*
 * Create a new graph instance.
 * @name: identifier for map pinning (e.g., "groutx")
 * @max_nodes: PROG_ARRAY size (0 = use EGL_DEFAULT_MAX_NODES).
 *             Set at map creation time via bpf_map__set_max_entries()
 *             before loading BPF objects.
 */
struct egl_graph *egl_graph_create(const char *name, int max_nodes);

/*
 * Add a node (loads BPF ELF, inserts prog fd into PROG_ARRAY at index).
 * Works for any BPF program type -- the graph doesn't care if it's
 * XDP, TC, or something else.
 */
int egl_graph_add_node(struct egl_graph *g, int index,
                       const char *bpf_obj_path, const char *prog_name);

/* Remove a node (sets prog_array[index] to empty) */
int egl_graph_remove_node(struct egl_graph *g, int index);

/* Detach and cleanup */
void egl_graph_destroy(struct egl_graph *g);

/*
 * Validate DAG: returns 0 if valid, -ELOOP if cycle detected.
 * The edge topology must be registered via egl_graph_add_edge().
 */
int egl_graph_validate_dag(const struct egl_graph *g);

/* Register a directed edge from node `from` to node `to`.
 * Used for DAG validation only -- the actual tail calls happen
 * in BPF code, not in userspace. */
int egl_graph_add_edge(struct egl_graph *g, int from, int to);

/* Remove an edge */
int egl_graph_remove_edge(struct egl_graph *g, int from, int to);

/*
 * Add an edge only if it doesn't create a cycle.
 * Atomically adds the edge, validates the DAG, and removes the edge
 * if validation fails. Returns -ELOOP if the edge would create a cycle.
 */
int egl_graph_add_edge_safe(struct egl_graph *g, int from, int to);

/* Get the PROG_ARRAY map fd (for BPF programs that need to
 * reference it via bpf_map__reuse_fd) */
int egl_graph_get_prog_array_fd(const struct egl_graph *g);

/* Get the stats map fd */
int egl_graph_get_stats_fd(const struct egl_graph *g);

/*
 * Get the BPF program fd for a loaded node.
 * Returns the fd on success, -EINVAL or -ENOENT on failure.
 * The fd is owned by the graph — do NOT close it.
 */
int egl_graph_get_node_fd(const struct egl_graph *g, int index);

/*
 * Get any pinned map fd by name.
 * Constructs <pin_dir>/<map_name>, calls bpf_obj_get().
 * Returns fd on success, negative errno on failure.
 * The caller does NOT own the returned fd — do NOT close it.
 */
int egl_graph_get_map_fd(const struct egl_graph *g, const char *map_name);

/*
 * Get the BPF object path and program name for a loaded node.
 * Returns 0 if the node exists, -ENOENT otherwise.
 * Either pointer may be NULL if not needed.
 * The returned strings are owned by the graph — do NOT free them.
 */
int egl_graph_get_node_info(const struct egl_graph *g, int index,
                            const char **bpf_obj_path,
                            const char **prog_name);

#endif /* EGL_GRAPH_H */
