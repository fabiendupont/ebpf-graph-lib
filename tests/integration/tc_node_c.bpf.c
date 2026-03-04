/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * TC node C — terminal node in a 3-node TC pipeline test.
 * Increments stats and returns TC_ACT_OK.
 */

#ifndef __BPF__
#define __BPF__
#endif

#include <egl/bpf/egl_common.bpf.h>

#define NODE_ID 2

SEC("tc")
int tc_node_c(struct __sk_buff *skb)
{
    EGL_STATS_INC_IN(egl_node_stats, NODE_ID, skb->len);
    EGL_STATS_INC_OUT(egl_node_stats, NODE_ID, skb->len);
    return 0;
}

char _license[] SEC("license") = "BSD";
