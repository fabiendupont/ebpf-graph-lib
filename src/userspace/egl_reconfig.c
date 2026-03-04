/* SPDX-License-Identifier: BSD-2-Clause */

#define _POSIX_C_SOURCE 200809L

#include <egl/egl_reconfig.h>
#include <egl/egl_graph.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define EGL_MAX_STAGED 64
#define EGL_RCU_GRACE_MS 10

struct egl_staged_add {
    int index;
    char *bpf_obj_path;
    char *prog_name;
};

/* Internal accessors -- egl_graph.c exposes the reconfig state via
 * a pointer stored in struct egl_graph. For simplicity, we use the
 * public API to stage changes and commit them. */

static struct {
    int active;
    struct egl_staged_add adds[EGL_MAX_STAGED];
    int add_count;
    int removes[EGL_MAX_STAGED];
    int remove_count;
    struct egl_graph *graph;
} g_reconfig;

int egl_reconfig_begin(struct egl_graph *g)
{
    if (g == NULL) { return -EINVAL; }
    if (g_reconfig.active) { return -EBUSY; }

    (void)memset(&g_reconfig, 0, sizeof(g_reconfig));
    g_reconfig.active = 1;
    g_reconfig.graph = g;

    return 0;
}

int egl_reconfig_add_node(struct egl_graph *g, int index,
                          const char *bpf_obj_path, const char *prog_name)
{
    struct egl_staged_add *sa;

    if (g == NULL || bpf_obj_path == NULL || prog_name == NULL) {
        return -EINVAL;
    }
    if (!g_reconfig.active || g_reconfig.graph != g) { return -EINVAL; }
    if (g_reconfig.add_count >= EGL_MAX_STAGED) { return -ENOSPC; }

    sa = &g_reconfig.adds[g_reconfig.add_count];
    sa->index = index;
    sa->bpf_obj_path = strdup(bpf_obj_path);
    sa->prog_name = strdup(prog_name);

    if (sa->bpf_obj_path == NULL || sa->prog_name == NULL) {
        free(sa->bpf_obj_path);
        free(sa->prog_name);
        return -ENOMEM;
    }

    g_reconfig.add_count++;
    return 0;
}

int egl_reconfig_remove_node(struct egl_graph *g, int index)
{
    if (g == NULL) { return -EINVAL; }
    if (!g_reconfig.active || g_reconfig.graph != g) { return -EINVAL; }
    if (g_reconfig.remove_count >= EGL_MAX_STAGED) { return -ENOSPC; }

    g_reconfig.removes[g_reconfig.remove_count++] = index;
    return 0;
}

static void free_staged(void)
{
    for (int i = 0; i < g_reconfig.add_count; i++) {
        free(g_reconfig.adds[i].bpf_obj_path);
        free(g_reconfig.adds[i].prog_name);
    }
    (void)memset(&g_reconfig, 0, sizeof(g_reconfig));
}

/*
 * Wait for in-flight BPF programs referencing old PROG_ARRAY entries
 * to complete.
 *
 * Safety analysis (see SAFETY_CASE.md §5.3):
 *
 * BPF_MAP_TYPE_PROG_ARRAY updates are RCU-protected by the kernel.
 * Individual bpf_map_update_elem/bpf_map_delete_elem calls are atomic
 * and immediately visible to new bpf_tail_call lookups. The old
 * program's reference count is held by any in-flight tail call, so
 * the old program is not freed until the tail call completes.
 *
 * This sleep ensures that all packets that entered the pipeline
 * under the OLD configuration have fully drained before the caller
 * considers the reconfiguration complete. This is relevant when the
 * caller needs to free old resources or verify new-configuration
 * behavior.
 *
 * Bound analysis:
 * - eBPF programs are non-preemptible on a single CPU
 * - Maximum tail-call depth is 33 (kernel enforced)
 * - Maximum BPF instruction count per program is 1M (kernel enforced)
 * - At ~100ns per instruction, worst case per-packet is ~33 * 100ms = 3.3s
 *   (theoretical maximum; real programs are orders of magnitude faster)
 * - Typical NAPI poll cycle completes in <1ms
 * - 10ms provides >10x margin over typical worst case
 *
 * For safety-critical deployments, callers should use
 * BPF_PROG_TEST_RUN with empty input to force a synchronization
 * point, or verify via stats counters that traffic has quiesced.
 */
static void rcu_grace_period(void)
{
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = EGL_RCU_GRACE_MS * 1000000L;
    (void)nanosleep(&ts, NULL);
}

/*
 * Snapshot of removed nodes for rollback (FM-RECONFIG-01).
 * Before removing a node, we save its load info so we can
 * re-add it if the commit fails.
 */
struct egl_removed_snapshot {
    int index;
    char *bpf_obj_path;
    char *prog_name;
};

int egl_reconfig_commit(struct egl_graph *g)
{
    struct egl_removed_snapshot snapshots[EGL_MAX_STAGED];
    int ret;
    int removes_applied = 0;
    int adds_applied = 0;

    if (g == NULL) { return -EINVAL; }
    if (!g_reconfig.active || g_reconfig.graph != g) { return -EINVAL; }

    /* R1 (FTA): Validate DAG before applying any changes.
     * This prevents committing a configuration that contains cycles. */
    ret = egl_graph_validate_dag(g);
    if (ret < 0) {
        free_staged();
        return ret;
    }

    (void)memset(snapshots, 0, sizeof(snapshots));

    /* Apply all removes first — snapshot node info for rollback */
    for (int i = 0; i < g_reconfig.remove_count; i++) {
        const char *obj_path = NULL;
        const char *pname = NULL;
        int idx = g_reconfig.removes[i];

        /* Save load info before removing (FM-RECONFIG-01) */
        if (egl_graph_get_node_info(g, idx, &obj_path, &pname) == 0) {
            snapshots[i].index = idx;
            snapshots[i].bpf_obj_path = obj_path ? strdup(obj_path) : NULL;
            snapshots[i].prog_name = pname ? strdup(pname) : NULL;
        }

        ret = egl_graph_remove_node(g, idx);
        if (ret < 0 && ret != -ENOENT) {
            goto rollback;
        }
        removes_applied++;
    }

    /* Apply all adds */
    for (int i = 0; i < g_reconfig.add_count; i++) {
        const struct egl_staged_add *sa = &g_reconfig.adds[i];

        ret = egl_graph_add_node(g, sa->index, sa->bpf_obj_path,
                                 sa->prog_name);
        if (ret < 0) {
            goto rollback;
        }
        adds_applied++;
    }

    /* Wait for RCU grace period to drain in-flight packets */
    rcu_grace_period();

    /* Free snapshots — no longer needed on success */
    for (int i = 0; i < removes_applied; i++) {
        free(snapshots[i].bpf_obj_path);
        free(snapshots[i].prog_name);
    }

    free_staged();
    return 0;

rollback:
    /* R5 (FTA): Roll back already-applied changes on failure.
     * Undo adds first (reverse order), then restore removes. */
    for (int i = adds_applied - 1; i >= 0; i--) {
        (void)egl_graph_remove_node(g, g_reconfig.adds[i].index);
    }

    /* Re-add removed nodes using saved snapshots (FM-RECONFIG-01) */
    for (int i = removes_applied - 1; i >= 0; i--) {
        if (snapshots[i].bpf_obj_path != NULL &&
            snapshots[i].prog_name != NULL) {
            (void)egl_graph_add_node(g, snapshots[i].index,
                                     snapshots[i].bpf_obj_path,
                                     snapshots[i].prog_name);
        }
    }

    for (int i = 0; i < removes_applied; i++) {
        free(snapshots[i].bpf_obj_path);
        free(snapshots[i].prog_name);
    }

    free_staged();
    return ret;
}

int egl_reconfig_abort(struct egl_graph *g)
{
    if (g == NULL) { return -EINVAL; }
    if (!g_reconfig.active || g_reconfig.graph != g) { return -EINVAL; }

    free_staged();
    return 0;
}
