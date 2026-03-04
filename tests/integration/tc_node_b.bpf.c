/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * TC node B — middle node in a 3-node TC pipeline test.
 * Increments stats and tail-calls to node C (index 2).
 */

#ifndef __BPF__
#define __BPF__
#endif

#include <egl/bpf/egl_common.bpf.h>

#define NODE_ID 1
#define NEXT_NODE 2

SEC("tc")
int tc_node_b(struct __sk_buff *skb)
{
    EGL_STATS_INC_IN(egl_node_stats, NODE_ID, skb->len);
    EGL_STATS_INC_OUT(egl_node_stats, NODE_ID, skb->len);
    EGL_NEXT(skb, egl_prog_array, NEXT_NODE);
    return 0;
}

char _license[] SEC("license") = "BSD";
