/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * TC chain example — 2-node TC classifier chain.
 *
 * Loads two TC BPF programs (tc_node_a and tc_node_b) into a graph,
 * validates the DAG, and prints the graph state.
 *
 * Usage: tc_chain <tc_node_a.bpf.o> <tc_node_b.bpf.o>
 *
 * Requires root or CAP_BPF + CAP_NET_ADMIN.
 */

#include <egl/egl_graph.h>
#include <egl/egl_stats.h>
#include <egl/egl_types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_stats(struct egl_graph *g, int node_id, const char *name)
{
    struct egl_node_stats stats;
    int ret;

    ret = egl_stats_read(g, node_id, &stats);
    if (ret < 0) {
        fprintf(stderr, "  %s: failed to read stats (%s)\n",
                name, strerror(-ret));
        return;
    }

    printf("  %s [%d]: in=%llu/%llu out=%llu/%llu drops=%llu errors=%llu\n",
           name, node_id,
           (unsigned long long)stats.in_count,
           (unsigned long long)stats.in_bytes,
           (unsigned long long)stats.out_count,
           (unsigned long long)stats.out_bytes,
           (unsigned long long)stats.drops,
           (unsigned long long)stats.errors);
}

int main(int argc, char **argv)
{
    struct egl_graph *g;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <tc_node_a.bpf.o> <tc_node_b.bpf.o>\n",
                argv[0]);
        return 1;
    }

    printf("Creating TC chain graph...\n");

    g = egl_graph_create("tc_chain", 8);
    if (g == NULL) {
        fprintf(stderr, "Failed to create graph\n");
        return 1;
    }

    /* Load node A at index 0 */
    printf("Loading node A from %s...\n", argv[1]);
    ret = egl_graph_add_node(g, 0, argv[1], "tc_node_a");
    if (ret < 0) {
        fprintf(stderr, "Failed to add node A: %s\n", strerror(-ret));
        egl_graph_destroy(g);
        return 1;
    }

    /* Load node B at index 1 */
    printf("Loading node B from %s...\n", argv[2]);
    ret = egl_graph_add_node(g, 1, argv[2], "tc_node_b");
    if (ret < 0) {
        fprintf(stderr, "Failed to add node B: %s\n", strerror(-ret));
        egl_graph_destroy(g);
        return 1;
    }

    /* Register edge: A -> B */
    ret = egl_graph_add_edge(g, 0, 1);
    if (ret < 0) {
        fprintf(stderr, "Failed to add edge: %s\n", strerror(-ret));
        egl_graph_destroy(g);
        return 1;
    }

    /* Validate DAG */
    ret = egl_graph_validate_dag(g);
    if (ret < 0) {
        fprintf(stderr, "DAG validation failed: %s\n", strerror(-ret));
        egl_graph_destroy(g);
        return 1;
    }

    printf("Graph validated successfully (DAG is acyclic)\n");
    printf("PROG_ARRAY fd: %d\n", egl_graph_get_prog_array_fd(g));
    printf("Stats fd: %d\n", egl_graph_get_stats_fd(g));

    /* Print initial stats */
    printf("\nNode statistics:\n");
    print_stats(g, 0, "node_a");
    print_stats(g, 1, "node_b");

    printf("\nTo attach node A as a TC classifier:\n");
    printf("  tc qdisc add dev <iface> clsact\n");
    printf("  tc filter add dev <iface> ingress bpf da fd %d\n",
           egl_graph_get_prog_array_fd(g));

    /* Cleanup */
    printf("\nDestroying graph...\n");
    egl_graph_destroy(g);
    printf("Done.\n");

    return 0;
}
