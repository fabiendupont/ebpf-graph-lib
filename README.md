# ebpf-graph-lib

Generic C library for building modular, formally verifiable eBPF
processing pipelines using tail calls.

## Overview

ebpf-graph-lib provides a program-type-agnostic framework for constructing
eBPF processing graphs. Each node is an independent BPF program connected
via tail calls through `BPF_MAP_TYPE_PROG_ARRAY`. The library handles
graph topology management, DAG validation, node lifecycle, per-node
statistics, and atomic reconfiguration.

This library is the foundation for program-type-specific layers like
[xdp-graph-lib](../xdp-graph-lib/) (XDP) and can also be used directly
for TC, socket filter, or other eBPF program types.

## Features

- **Program-type agnostic**: Works with XDP, TC, socket filters, etc.
- **Tail-call chaining**: Zero-overhead node transitions via PROG_ARRAY
- **DAG validation**: Cycle detection prevents infinite tail-call loops
- **Per-node statistics**: In/out/drop/error counters via PERCPU_ARRAY maps
- **Atomic reconfiguration**: Shadow PROG_ARRAY swap for zero-downtime updates
- **libbpf CO-RE loader**: BPF object loading with map pinning/sharing
- **FuSa-ready**: CBMC + TLA+ verification

## Building

```sh
meson setup builddir
meson compile -C builddir
meson test -C builddir
meson install -C builddir          # installs headers, libegl.a, egl.pc
```

## Using in a Downstream Project

### Meson (recommended)

```meson
egl_dep = dependency('egl')

my_app = executable('my_app',
    'main.c',
    dependencies: [egl_dep],
)
```

### pkg-config

```sh
cc $(pkg-config --cflags egl) -c main.c
cc main.o $(pkg-config --libs egl) -o my_app
```

### Compiling BPF Node Programs

BPF nodes must be compiled with `clang -target bpf`. Each node includes
`egl_common.bpf.h` to get the shared map declarations.

```sh
# Compile a BPF node object
clang -target bpf -D__BPF__ \
    $(pkg-config --cflags egl) \
    -I /usr/include \
    -O2 -g \
    -c my_node.bpf.c -o my_node.bpf.o
```

Minimal BPF node example:

```c
/* my_node.bpf.c */
#include <egl/bpf/egl_common.bpf.h>

#define MY_NODE_ID 0

SEC("tc")    /* or SEC("xdp"), SEC("socket"), etc. */
int my_node(struct __sk_buff *skb)
{
    EGL_STATS_INC_IN(egl_node_stats, MY_NODE_ID, skb->len);

    /* ... node-specific processing ... */

    EGL_STATS_INC_OUT(egl_node_stats, MY_NODE_ID, skb->len);
    EGL_NEXT(skb, egl_prog_array, 1);  /* tail-call to node 1 */

    return 0;  /* fall-through if tail call fails */
}

char _license[] SEC("license") = "BSD";
```

### Meson Helper for BPF Compilation

Add this to your `meson.build` to compile BPF objects:

```meson
clang = find_program('clang')
egl_dep = dependency('egl')

# Extract include path from pkg-config
egl_cflags = egl_dep.partial_dependency(compile_args: true)

bpf_node = custom_target('my_node.bpf.o',
    input: 'my_node.bpf.c',
    output: 'my_node.bpf.o',
    command: [clang,
        '-target', 'bpf', '-D__BPF__',
        '-I', meson.project_source_root() / 'include',
        '-O2', '-g',
        '-c', '@INPUT@', '-o', '@OUTPUT@'],
)
```

## Dependencies

- libbpf >= 1.0
- libelf
- clang (for BPF node compilation)

## License

BSD-3-Clause
