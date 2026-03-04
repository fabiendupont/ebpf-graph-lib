/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * TC node B — second (terminal) node in a 2-node TC classifier chain.
 * Increments stats and returns TC_ACT_OK.
 */

#ifndef __BPF__
#define __BPF__
#endif

#include "../../src/bpf/egl_common.bpf.h"

#define NODE_ID 1

SEC("tc")
int tc_node_b(struct __sk_buff *skb)
{
    EGL_STATS_INC_IN(egl_node_stats, NODE_ID, skb->len);

    /* Terminal node — process and return */

    EGL_STATS_INC_OUT(egl_node_stats, NODE_ID, skb->len);

    return 0; /* TC_ACT_OK */
}

char _license[] SEC("license") = "BSD";
