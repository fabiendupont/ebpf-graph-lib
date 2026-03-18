/* SPDX-License-Identifier: BSD-2-Clause */

#define _POSIX_C_SOURCE 200809L

#include <egl/egl_graph.h>
#include <egl/egl_types.h>
#include <egl/egl_loader.h>
#include "egl_internal.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define EGL_PIN_BASE "/sys/fs/bpf/egl"
#define EGL_MAX_CACHED_MAPS 32
#define EGL_MAX_STAGED 64

struct egl_node_info {
    char *bpf_obj_path;
    char *prog_name;
};

struct egl_cached_map {
    char *name;
    int fd;
};

struct egl_staged_add {
    int index;
    char *bpf_obj_path;
    char *prog_name;
};

struct egl_reconfig_state {
    int active;
    struct egl_staged_add adds[EGL_MAX_STAGED];
    int add_count;
    int removes[EGL_MAX_STAGED];
    int remove_count;
};

struct egl_graph {
    char *name;
    int max_nodes;
    int prog_array_fd;
    int stats_fd;
    struct bpf_object **node_objs;
    int *node_fds;
    struct egl_node_info *node_info;
    /* Adjacency matrix for DAG validation: edges[from * max_nodes + to] */
    unsigned char *edges;
    /* Index reservation bitmap: 1 = reserved/allocated, 0 = free */
    unsigned char *reserved;
    char *pin_dir;
    /* Shared PROG_ARRAY pin path (NULL = create own, non-NULL = join/create) */
    char *shared_prog_array_path;
    /* Cached application map fds — all owned by the graph */
    struct egl_cached_map cached_maps[EGL_MAX_CACHED_MAPS];
    int cached_map_count;
    /* Per-graph reconfiguration state */
    struct egl_reconfig_state reconfig;
};

/* Forward declaration for use in egl_graph_create_shared */
void egl_graph_destroy(struct egl_graph *g);

static int make_pin_dir(const char *path)
{
    char tmp[256];
    char *p;
    int ret;

    (void)snprintf(tmp, sizeof(tmp), "%s", path);

    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            ret = mkdir(tmp, 0755);
            if (ret < 0 && errno != EEXIST) { return -errno; }
            *p = '/';
        }
    }

    ret = mkdir(tmp, 0755);
    if (ret < 0 && errno != EEXIST) { return -errno; }

    return 0;
}

struct egl_graph *egl_graph_create(const char *name, int max_nodes)
{
    struct egl_graph *g;
    int mn;
    size_t edge_sz;

    if (name == NULL) { return NULL; }

    mn = (max_nodes <= 0) ? EGL_DEFAULT_MAX_NODES : max_nodes;

    g = calloc(1, sizeof(*g));
    if (g == NULL) { return NULL; }

    g->name = strdup(name);
    if (g->name == NULL) { goto err_name; }

    g->max_nodes = mn;
    g->prog_array_fd = -1;
    g->stats_fd = -1;

    g->node_objs = calloc((size_t)mn, sizeof(*g->node_objs));
    if (g->node_objs == NULL) { goto err_objs; }

    g->node_fds = calloc((size_t)mn, sizeof(*g->node_fds));
    if (g->node_fds == NULL) { goto err_fds; }

    g->node_info = calloc((size_t)mn, sizeof(*g->node_info));
    if (g->node_info == NULL) { goto err_info; }

    for (int i = 0; i < mn; i++) {
        g->node_fds[i] = -1;
    }

    edge_sz = (size_t)mn * (size_t)mn;
    g->edges = calloc(edge_sz, sizeof(*g->edges));
    if (g->edges == NULL) { goto err_edges_alloc; }

    g->reserved = calloc((size_t)mn, sizeof(*g->reserved));
    if (g->reserved == NULL) { goto err_reserved; }

    /* Build pin directory path */
    {
        char buf[256];
        (void)snprintf(buf, sizeof(buf), "%s/%s", EGL_PIN_BASE, name);
        g->pin_dir = strdup(buf);
        if (g->pin_dir == NULL) { goto err_pin; }
    }

    return g;

err_pin:
    free(g->reserved);
err_reserved:
    free(g->edges);
err_edges_alloc:
    free(g->node_info);
err_info:
    free(g->node_fds);
err_fds:
    free(g->node_objs);
err_objs:
    free(g->name);
err_name:
    free(g);
    return NULL;
}

struct egl_graph *egl_graph_create_shared(const char *name, int max_nodes,
                                          const char *prog_array_pin_path)
{
    struct egl_graph *g;

    g = egl_graph_create(name, max_nodes);
    if (g == NULL)
        return NULL;

    if (prog_array_pin_path != NULL) {
        g->shared_prog_array_path = strdup(prog_array_pin_path);
        if (g->shared_prog_array_path == NULL) {
            egl_graph_destroy(g);
            return NULL;
        }
    }

    return g;
}

static int ensure_maps(struct egl_graph *g)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);

    if (g->prog_array_fd >= 0) { return 0; }

    /* Shared mode: try to open existing pinned PROG_ARRAY first */
    if (g->shared_prog_array_path != NULL) {
        g->prog_array_fd = bpf_obj_get(g->shared_prog_array_path);
        if (g->prog_array_fd >= 0)
            goto create_stats;
        /* Pin doesn't exist yet — create and pin below */
    }

    /* Create PROG_ARRAY */
    g->prog_array_fd = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY,
                                       "egl_prog_array",
                                       sizeof(__u32), sizeof(__u32),
                                       (__u32)g->max_nodes, &opts);
    if (g->prog_array_fd < 0) { return -errno; }

    /* Pin shared PROG_ARRAY if path specified */
    if (g->shared_prog_array_path != NULL) {
        int pin_ret = bpf_obj_pin(g->prog_array_fd,
                                  g->shared_prog_array_path);
        if (pin_ret < 0 && errno != EEXIST) {
            close(g->prog_array_fd);
            g->prog_array_fd = -1;
            return -errno;
        }
    }

create_stats:
    /* Create PERCPU_ARRAY for stats */
    g->stats_fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY,
                                  "egl_node_stats",
                                  sizeof(__u32),
                                  sizeof(struct egl_node_stats),
                                  (__u32)g->max_nodes, &opts);
    if (g->stats_fd < 0) {
        close(g->prog_array_fd);
        g->prog_array_fd = -1;
        return -errno;
    }

    /* Pin maps for sharing */
    {
        char path[512];
        int ret;

        ret = make_pin_dir(g->pin_dir);
        if (ret < 0) { return ret; }

        (void)snprintf(path, sizeof(path), "%s/egl_prog_array", g->pin_dir);
        ret = bpf_obj_pin(g->prog_array_fd, path);
        if (ret < 0 && errno != EEXIST) { return -errno; }

        (void)snprintf(path, sizeof(path), "%s/egl_node_stats", g->pin_dir);
        ret = bpf_obj_pin(g->stats_fd, path);
        if (ret < 0 && errno != EEXIST) { return -errno; }
    }

    return 0;
}

int egl_graph_add_node(struct egl_graph *g, int index,
                       const char *bpf_obj_path, const char *prog_name)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd;
    int ret;

    if (g == NULL || bpf_obj_path == NULL || prog_name == NULL) {
        return -EINVAL;
    }
    if (index < 0 || index >= g->max_nodes) { return -EINVAL; }
    if (g->node_objs[index] != NULL) { return -EEXIST; }

    /* Auto-reserve if not already reserved */
    if (g->reserved[index] == 0) {
        g->reserved[index] = 1;
    }

    ret = ensure_maps(g);
    if (ret < 0) { return ret; }

    /* Open and configure the BPF object */
    obj = bpf_object__open(bpf_obj_path);
    if (obj == NULL) { return -errno; }

    /* Reuse shared maps: prog_array, stats, and any previously pinned
     * application maps (fib4, neigh4, iface_mac, tx_ports, etc.) */
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);

        if (strcmp(map_name, "egl_prog_array") == 0) {
            ret = bpf_map__reuse_fd(map, g->prog_array_fd);
            if (ret < 0) { goto err_close; }
        } else if (strcmp(map_name, "egl_node_stats") == 0) {
            ret = bpf_map__reuse_fd(map, g->stats_fd);
            if (ret < 0) { goto err_close; }
        } else {
            /* Try to reuse a previously pinned map */
            char pin_path[512];
            int pinned_fd;

            (void)snprintf(pin_path, sizeof(pin_path),
                           "%s/%s", g->pin_dir, map_name);
            pinned_fd = bpf_obj_get(pin_path);
            if (pinned_fd >= 0) {
                ret = bpf_map__reuse_fd(map, pinned_fd);
                close(pinned_fd);
                if (ret < 0) { goto err_close; }
            }
        }
    }

    ret = bpf_object__load(obj);
    if (ret < 0) { goto err_close; }

    /* Pin any new application maps that aren't already pinned */
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        char pin_path[512];
        int map_fd;

        /* Skip maps managed by ensure_maps() */
        if (strcmp(map_name, "egl_prog_array") == 0) { continue; }
        if (strcmp(map_name, "egl_node_stats") == 0) { continue; }

        (void)snprintf(pin_path, sizeof(pin_path),
                       "%s/%s", g->pin_dir, map_name);

        /* Only pin if not already pinned */
        map_fd = bpf_obj_get(pin_path);
        if (map_fd >= 0) {
            close(map_fd);
            continue;
        }

        map_fd = bpf_map__fd(map);
        if (map_fd >= 0) {
            (void)bpf_obj_pin(map_fd, pin_path);
        }
    }

    /* Find the named program */
    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (prog == NULL) {
        ret = -ENOENT;
        goto err_close;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        ret = -ENOENT;
        goto err_close;
    }

    /* Insert into PROG_ARRAY */
    {
        __u32 key = (__u32)index;
        __u32 val = (__u32)prog_fd;

        ret = bpf_map_update_elem(g->prog_array_fd, &key, &val, BPF_ANY);
        if (ret < 0) {
            ret = -errno;
            goto err_close;
        }
    }

    g->node_objs[index] = obj;
    g->node_fds[index] = prog_fd;

    /* Save load info for rollback support (FM-RECONFIG-01) */
    g->node_info[index].bpf_obj_path = strdup(bpf_obj_path);
    g->node_info[index].prog_name = strdup(prog_name);

    return 0;

err_close:
    bpf_object__close(obj);
    return ret;
}

int egl_graph_remove_node(struct egl_graph *g, int index)
{
    __u32 key;

    if (g == NULL) { return -EINVAL; }
    if (index < 0 || index >= g->max_nodes) { return -EINVAL; }
    if (g->node_objs[index] == NULL) { return -ENOENT; }

    /* Remove from PROG_ARRAY */
    key = (__u32)index;
    (void)bpf_map_delete_elem(g->prog_array_fd, &key);

    /* Close BPF object */
    bpf_object__close(g->node_objs[index]);
    g->node_objs[index] = NULL;
    g->node_fds[index] = -1;

    /* Free saved load info */
    free(g->node_info[index].bpf_obj_path);
    free(g->node_info[index].prog_name);
    g->node_info[index].bpf_obj_path = NULL;
    g->node_info[index].prog_name = NULL;

    /* Release index reservation */
    g->reserved[index] = 0;

    /* Remove all edges involving this node */
    for (int i = 0; i < g->max_nodes; i++) {
        g->edges[index * g->max_nodes + i] = 0;
        g->edges[i * g->max_nodes + index] = 0;
    }

    return 0;
}

void egl_graph_destroy(struct egl_graph *g)
{
    if (g == NULL) { return; }

    /* Close all loaded BPF objects and free node info */
    for (int i = 0; i < g->max_nodes; i++) {
        if (g->node_objs[i] != NULL) {
            bpf_object__close(g->node_objs[i]);
        }
        free(g->node_info[i].bpf_obj_path);
        free(g->node_info[i].prog_name);
    }

    /* Unpin all maps in the pin directory */
    if (g->pin_dir != NULL) {
        DIR *dir;
        struct dirent *ent;

        dir = opendir(g->pin_dir);
        if (dir != NULL) {
            while ((ent = readdir(dir)) != NULL) {
                char path[512];

                if (ent->d_name[0] == '.') { continue; }

                (void)snprintf(path, sizeof(path),
                               "%s/%s", g->pin_dir, ent->d_name);
                (void)unlink(path);
            }
            closedir(dir);
        }

        (void)rmdir(g->pin_dir);
    }

    /* Close cached application map fds */
    for (int i = 0; i < g->cached_map_count; i++) {
        if (g->cached_maps[i].fd >= 0) { close(g->cached_maps[i].fd); }
        free(g->cached_maps[i].name);
    }

    if (g->prog_array_fd >= 0) { close(g->prog_array_fd); }
    if (g->stats_fd >= 0) { close(g->stats_fd); }

    free(g->node_objs);
    free(g->node_fds);
    free(g->node_info);
    free(g->edges);
    free(g->reserved);
    free(g->pin_dir);
    free(g->shared_prog_array_path);
    free(g->name);
    free(g);
}

int egl_graph_add_edge(struct egl_graph *g, int from, int to)
{
    if (g == NULL) { return -EINVAL; }
    if (from < 0 || from >= g->max_nodes) { return -EINVAL; }
    if (to < 0 || to >= g->max_nodes) { return -EINVAL; }

    g->edges[from * g->max_nodes + to] = 1;

    return 0;
}

int egl_graph_remove_edge(struct egl_graph *g, int from, int to)
{
    if (g == NULL) { return -EINVAL; }
    if (from < 0 || from >= g->max_nodes) { return -EINVAL; }
    if (to < 0 || to >= g->max_nodes) { return -EINVAL; }

    g->edges[from * g->max_nodes + to] = 0;

    return 0;
}

int egl_graph_add_edge_safe(struct egl_graph *g, int from, int to)
{
    int ret;

    ret = egl_graph_add_edge(g, from, to);
    if (ret < 0) { return ret; }

    ret = egl_graph_validate_dag(g);
    if (ret < 0) {
        /* Cycle detected — roll back the edge */
        g->edges[from * g->max_nodes + to] = 0;
        return -ELOOP;
    }

    return 0;
}

/*
 * DAG validation using Kahn's algorithm (BFS topological sort).
 * Returns 0 if the graph is a valid DAG, -ELOOP if a cycle exists.
 */
int egl_graph_validate_dag(const struct egl_graph *g)
{
    int *in_degree;
    int *queue;
    int head, tail;
    int processed;
    int node_count;
    int mn;

    if (g == NULL) { return -EINVAL; }

    mn = g->max_nodes;

    in_degree = calloc((size_t)mn, sizeof(*in_degree));
    if (in_degree == NULL) { return -ENOMEM; }

    queue = calloc((size_t)mn, sizeof(*queue));
    if (queue == NULL) {
        free(in_degree);
        return -ENOMEM;
    }

    /* Count how many nodes have edges and compute in-degrees */
    node_count = 0;
    for (int i = 0; i < mn; i++) {
        int has_edges = 0;
        for (int j = 0; j < mn; j++) {
            if (g->edges[i * mn + j] != 0) {
                in_degree[j]++;
                has_edges = 1;
            }
            if (g->edges[j * mn + i] != 0) {
                has_edges = 1;
            }
        }
        (void)has_edges;
    }

    /* Count nodes that participate in edges */
    for (int i = 0; i < mn; i++) {
        int participates = 0;
        for (int j = 0; j < mn; j++) {
            if (g->edges[i * mn + j] != 0 || g->edges[j * mn + i] != 0) {
                participates = 1;
                break;
            }
        }
        if (participates) { node_count++; }
    }

    /* If no edges, it's a valid DAG */
    if (node_count == 0) {
        free(queue);
        free(in_degree);
        return 0;
    }

    /* Enqueue nodes with in-degree 0 that participate in edges */
    head = 0;
    tail = 0;
    for (int i = 0; i < mn; i++) {
        int participates = 0;
        for (int j = 0; j < mn; j++) {
            if (g->edges[i * mn + j] != 0 || g->edges[j * mn + i] != 0) {
                participates = 1;
                break;
            }
        }
        if (participates && in_degree[i] == 0) {
            queue[tail++] = i;
        }
    }

    /* Process BFS */
    processed = 0;
    while (head < tail) {
        int node = queue[head++];
        processed++;

        for (int j = 0; j < mn; j++) {
            if (g->edges[node * mn + j] != 0) {
                in_degree[j]--;
                if (in_degree[j] == 0) {
                    queue[tail++] = j;
                }
            }
        }
    }

    free(queue);
    free(in_degree);

    return (processed == node_count) ? 0 : -ELOOP;
}

int egl_graph_alloc_index(struct egl_graph *g)
{
    if (g == NULL) { return -EINVAL; }

    for (int i = 0; i < g->max_nodes; i++) {
        if (g->reserved[i] == 0) {
            g->reserved[i] = 1;
            return i;
        }
    }

    return -ENOSPC;
}

int egl_graph_reserve_index(struct egl_graph *g, int index)
{
    if (g == NULL) { return -EINVAL; }
    if (index < 0 || index >= g->max_nodes) { return -EINVAL; }
    if (g->reserved[index] != 0) { return -EEXIST; }

    g->reserved[index] = 1;

    return 0;
}

int egl_graph_free_index(struct egl_graph *g, int index)
{
    if (g == NULL) { return -EINVAL; }
    if (index < 0 || index >= g->max_nodes) { return -EINVAL; }
    if (g->reserved[index] == 0) { return -ENOENT; }
    if (g->node_objs[index] != NULL) { return -EBUSY; }

    g->reserved[index] = 0;

    return 0;
}

int egl_graph_get_prog_array_fd(const struct egl_graph *g)
{
    if (g == NULL) { return -EINVAL; }
    return g->prog_array_fd;
}

int egl_graph_get_stats_fd(const struct egl_graph *g)
{
    if (g == NULL) { return -EINVAL; }
    return g->stats_fd;
}

int egl_graph_get_node_fd(const struct egl_graph *g, int index)
{
    if (g == NULL) { return -EINVAL; }
    if (index < 0 || index >= g->max_nodes) { return -EINVAL; }
    if (g->node_fds[index] < 0) { return -ENOENT; }

    return g->node_fds[index];
}

int egl_graph_get_node_info(const struct egl_graph *g, int index,
                            const char **bpf_obj_path,
                            const char **prog_name)
{
    if (g == NULL) { return -EINVAL; }
    if (index < 0 || index >= g->max_nodes) { return -EINVAL; }
    if (g->node_objs[index] == NULL) { return -ENOENT; }

    if (bpf_obj_path != NULL) {
        *bpf_obj_path = g->node_info[index].bpf_obj_path;
    }
    if (prog_name != NULL) {
        *prog_name = g->node_info[index].prog_name;
    }

    return 0;
}

int egl_graph_get_map_fd(const struct egl_graph *g, const char *map_name)
{
    /* Cast away const: caching is an internal detail that doesn't change
     * the logical state visible to the caller. */
    struct egl_graph *mg = (struct egl_graph *)(uintptr_t)g;
    char path[512];
    int fd;

    if (g == NULL || map_name == NULL) { return -EINVAL; }
    if (g->pin_dir == NULL) { return -ENOENT; }

    /* Fast path for well-known maps */
    if (strcmp(map_name, "egl_prog_array") == 0) {
        return g->prog_array_fd;
    }
    if (strcmp(map_name, "egl_node_stats") == 0) {
        return g->stats_fd;
    }

    /* Check cache first */
    for (int i = 0; i < g->cached_map_count; i++) {
        if (strcmp(g->cached_maps[i].name, map_name) == 0) {
            return g->cached_maps[i].fd;
        }
    }

    /* Application maps: open from pin directory and cache */
    (void)snprintf(path, sizeof(path), "%s/%s", g->pin_dir, map_name);
    fd = bpf_obj_get(path);
    if (fd < 0) { return -errno; }

    if (mg->cached_map_count < EGL_MAX_CACHED_MAPS) {
        mg->cached_maps[mg->cached_map_count].name = strdup(map_name);
        if (mg->cached_maps[mg->cached_map_count].name != NULL) {
            mg->cached_maps[mg->cached_map_count].fd = fd;
            mg->cached_map_count++;
        }
    }

    return fd;
}

int egl_graph_get_max_nodes(const struct egl_graph *g)
{
    if (g == NULL) { return -EINVAL; }
    return g->max_nodes;
}

/* --- Internal reconfig state management --- */

int egl_reconfig_begin_internal(struct egl_graph *g)
{
    if (g->reconfig.active) { return -EBUSY; }

    (void)memset(&g->reconfig, 0, sizeof(g->reconfig));
    g->reconfig.active = 1;

    return 0;
}

int egl_reconfig_clear_internal(struct egl_graph *g)
{
    if (!g->reconfig.active) { return -EINVAL; }

    for (int i = 0; i < g->reconfig.add_count; i++) {
        free(g->reconfig.adds[i].bpf_obj_path);
        free(g->reconfig.adds[i].prog_name);
    }
    (void)memset(&g->reconfig, 0, sizeof(g->reconfig));

    return 0;
}

int egl_reconfig_stage_add(struct egl_graph *g, int index,
                           const char *bpf_obj_path, const char *prog_name)
{
    struct egl_staged_add *sa;

    if (!g->reconfig.active) { return -EINVAL; }
    if (g->reconfig.add_count >= EGL_MAX_STAGED) { return -ENOSPC; }

    sa = &g->reconfig.adds[g->reconfig.add_count];
    sa->index = index;
    sa->bpf_obj_path = strdup(bpf_obj_path);
    sa->prog_name = strdup(prog_name);

    if (sa->bpf_obj_path == NULL || sa->prog_name == NULL) {
        free(sa->bpf_obj_path);
        free(sa->prog_name);
        return -ENOMEM;
    }

    g->reconfig.add_count++;
    return 0;
}

int egl_reconfig_stage_remove(struct egl_graph *g, int index)
{
    if (!g->reconfig.active) { return -EINVAL; }
    if (g->reconfig.remove_count >= EGL_MAX_STAGED) { return -ENOSPC; }

    g->reconfig.removes[g->reconfig.remove_count++] = index;
    return 0;
}

int egl_reconfig_get_counts(const struct egl_graph *g,
                            int *add_count, int *remove_count)
{
    if (!g->reconfig.active) { return -EINVAL; }

    *add_count = g->reconfig.add_count;
    *remove_count = g->reconfig.remove_count;
    return 0;
}

int egl_reconfig_get_remove_index(const struct egl_graph *g, int i)
{
    return g->reconfig.removes[i];
}

void egl_reconfig_get_add_entry(const struct egl_graph *g, int i,
                                int *index, const char **bpf_obj_path,
                                const char **prog_name)
{
    *index = g->reconfig.adds[i].index;
    *bpf_obj_path = g->reconfig.adds[i].bpf_obj_path;
    *prog_name = g->reconfig.adds[i].prog_name;
}
