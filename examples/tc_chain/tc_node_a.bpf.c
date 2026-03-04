/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * TC node A — first node in a 2-node TC classifier chain.
 * Increments stats and tail-calls to node B (index 1).
 */

#ifndef __BPF__
#define __BPF__
#endif

#include "../../src/bpf/egl_common.bpf.h"

#define NODE_ID 0
#define NEXT_NODE 1

SEC("tc")
int tc_node_a(struct __sk_buff *skb)
{
    EGL_STATS_INC_IN(egl_node_stats, NODE_ID, skb->len);

    /* Process: in a real application, this would inspect/modify
     * the packet. For this example, we just pass through. */

    EGL_STATS_INC_OUT(egl_node_stats, NODE_ID, skb->len);

    /* Tail-call to next node */
    EGL_NEXT(skb, egl_prog_array, NEXT_NODE);

    /* If tail call fails (node not present), return TC_ACT_OK */
    return 0; /* TC_ACT_OK */
}

char _license[] SEC("license") = "BSD";
