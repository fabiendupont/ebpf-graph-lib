# Software Architecture Document — ebpf-graph-lib

**Document Version**: 0.1.0
**Standard**: ISO 26262:2018 Part 6, §7 (Software Architectural Design)

---

## 1. Purpose and Scope

This document describes the software architecture of ebpf-graph-lib
(`libegl.a`), a generic C11 library for building modular eBPF
processing pipelines using BPF tail calls.

**In scope**: All userspace library code and BPF header macros.

**Out of scope**: Downstream libraries (xdp-graph-lib), BPF node
programs (application-specific), kernel internals, interface attachment.

---

## 2. Architectural Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                           │
│             (e.g., xdp-hsr-prp, xdp-iec61850)                   │
├─────────────────────────────────────────────────────────────────┤
│              Program-Type Library (out of scope)                │
│  (e.g., xdp-graph-lib: XDP actions, metadata, DEVMAP)           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────── ebpf-graph-lib ───────────────────────┐  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐   │  │
│  │  │  egl_graph  │  │ egl_loader  │  │   egl_reconfig   │   │  │
│  │  │             │  │             │  │                  │   │  │
│  │  │ - create    │  │ - open      │  │ - begin          │   │  │
│  │  │ - add_node  │──│ - pin_maps  │  │ - add_node       │   │  │
│  │  │ - remove    │  │ - reuse     │  │ - remove_node    │   │  │
│  │  │ - validate  │  │ - close     │  │ - commit/abort   │   │  │
│  │  │ - destroy   │  │             │  │                  │   │  │
│  │  └──────┬──────┘  └──────┬──────┘  └─────────┬────────┘   │  │
│  │         │                │                   │            │  │
│  │  ┌──────┴────────────────┴───────────────────┴─────────┐  │  │
│  │  │                    egl_stats                        │  │  │
│  │  │  - read (aggregate PERCPU_ARRAY across CPUs)        │  │  │
│  │  │  - read_all                                         │  │  │
│  │  │  - reset                                            │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                                                           │  │
│  │  ┌─── BPF Headers (compiled with clang -target bpf) ───┐  │  │
│  │  │  egl_types.h   egl_node.h   egl_edge.h  egl_stats.h │  │  │
│  │  │  egl_common.bpf.h (includes all + declares maps)    │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                          libbpf                                 │
│  bpf_object__open, bpf_object__load, bpf_map__reuse_fd,         │
│  bpf_map__pin, bpf_obj_pin, bpf_obj_get, bpf_map_create         │
├─────────────────────────────────────────────────────────────────┤
│                       Linux Kernel                              │
│  BPF subsystem, PROG_ARRAY, PERCPU_ARRAY, bpf_tail_call,        │
│  eBPF verifier, MAX_TAIL_CALL_CNT (33)                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Design

### 3.1 egl_graph (Core Component)

**File**: `src/userspace/egl_graph.c`
**Header**: `include/egl/egl_graph.h`
**Safety relevance**: High

**Responsibilities**:
- Graph lifecycle management (create, destroy)
- BPF node loading into PROG_ARRAY (add_node, remove_node)
- DAG topology tracking (adjacency matrix)
- DAG validation via Kahn's algorithm (validate_dag)
- BPF map creation and pinning (ensure_maps)

**Internal state** (`struct egl_graph` — opaque):

```
struct egl_graph {
    char *name;              // Graph instance name (for pin paths)
    int max_nodes;           // PROG_ARRAY size (from create)
    int prog_array_fd;       // BPF_MAP_TYPE_PROG_ARRAY fd
    int stats_fd;            // BPF_MAP_TYPE_PERCPU_ARRAY fd
    struct bpf_object **node_objs;  // [max_nodes] loaded BPF objects
    int *node_fds;                  // [max_nodes] program fds
    unsigned char *edges;           // [max_nodes * max_nodes] adjacency matrix
    char *pin_dir;                  // "/sys/fs/bpf/egl/<name>/"
};
```

**Allocation strategy**: All arrays are dynamically allocated in
`egl_graph_create()` based on `max_nodes`. No fixed-size arrays.
Allocation failure at any point triggers cleanup via goto-chain
and returns NULL.

**DAG validation algorithm**: Kahn's algorithm (BFS topological sort).

```
1. Compute in-degree for each node that participates in edges
2. Enqueue all participating nodes with in-degree = 0
3. While queue is not empty:
   a. Dequeue node, increment processed count
   b. For each outgoing edge, decrement target's in-degree
   c. If target's in-degree reaches 0, enqueue it
4. If processed < participating_node_count → cycle exists → return -ELOOP
5. Otherwise → valid DAG → return 0
```

**Formally verified**: CBMC proves this implementation agrees with a
DFS oracle for all graphs up to N=5 (2^25 edge combinations).

### 3.2 egl_loader (BPF Loading Component)

**File**: `src/userspace/egl_loader.c`
**Header**: `include/egl/egl_loader.h`
**Safety relevance**: Medium

**Responsibilities**:
- BPF object file loading via libbpf
- Program fd retrieval by name
- Program type inspection
- Map pinning for cross-object sharing
- Map reuse from pinned paths

**Design pattern**: Handle-based API. `egl_loader_open()` returns
an opaque `struct egl_bpf_prog *` handle. All subsequent operations
take this handle. `egl_loader_close()` releases all resources.

**Map sharing mechanism**:

```
Graph creates maps (ensure_maps)
    │
    ▼
First node loaded ──► bpf_map__reuse_fd(map, graph's prog_array_fd)
    │                  bpf_map__reuse_fd(map, graph's stats_fd)
    ▼
Second node loaded ──► same reuse_fd pattern
    │
    ▼
All nodes share the same PROG_ARRAY and stats maps
```

### 3.3 egl_reconfig (Reconfiguration Component)

**File**: `src/userspace/egl_reconfig.c`
**Header**: `include/egl/egl_reconfig.h`
**Safety relevance**: High

**Responsibilities**:
- Staged graph reconfiguration (begin/commit/abort pattern)
- Serialized access (global staging area, one reconfig at a time)
- RCU grace period wait after commit

**State machine**:

```
                 begin()
    IDLE ─────────────────► ACTIVE
     ▲                        │
     │           ┌────────────┼────────────┐
     │           │            │            │
     │        add_node()  remove_node()    │
     │           │            │            │
     │           └────────────┼────────────┘
     │                        │
     │         commit()       │       abort()
     └────────────────────────┴────────────────► IDLE
```

**Commit order**: Removes are applied before adds. This allows
replacing a node at the same index in a single reconfig transaction.

**Concurrency model**: Global staging area (`g_reconfig`). Only one
reconfig can be active at a time. `begin()` returns -EBUSY if another
reconfig is in progress. This is a deliberate simplification —
per-graph staging is a documented potential improvement.

**RCU grace period**: After commit, `nanosleep(10ms)` waits for
in-flight packets to drain. See `egl_reconfig.c` for the bound
analysis documenting why 10ms is sufficient.

### 3.4 egl_stats (Statistics Component)

**File**: `src/userspace/egl_stats.c`
**Header**: `include/egl/egl_stats.h` (dual BPF/userspace)
**Safety relevance**: Low (monitoring only)

**Responsibilities**:
- Read per-node statistics from PERCPU_ARRAY, aggregate across CPUs
- Reset per-node statistics (zero all CPU entries)
- Bulk read (read_all) with graceful handling of missing nodes

**Aggregation algorithm**:

```
1. Query libbpf_num_possible_cpus()
2. Allocate percpu_vals[num_cpus]
3. bpf_map_lookup_elem(stats_fd, &node_id, percpu_vals)
4. Sum all CPU entries into output struct
5. Free percpu_vals
```

**BPF-side macros**: `EGL_STATS_INC_IN`, `EGL_STATS_INC_OUT`,
`EGL_STATS_INC_DROP`, `EGL_STATS_INC_ERROR` — atomic per-CPU
increments via `bpf_map_lookup_elem` + direct memory write.

### 3.5 BPF Headers (Node Contract)

**Files**: `include/egl/egl_types.h`, `egl_node.h`, `egl_edge.h`,
`egl_stats.h`, `src/bpf/egl_common.bpf.h`
**Safety relevance**: High (defines the BPF node contract)

**Node contract**: Every BPF node in the graph MUST:

1. Include `egl_common.bpf.h` to get shared map declarations
2. Use `EGL_NEXT(ctx, egl_prog_array, node_id)` for tail calls
3. Handle tail-call failure (fall-through path)
4. Use `EGL_STATS_INC_*` macros for observability
5. (Optional) Use `EGL_DEPTH_EXCEEDED` for application-level depth limiting

**Program-type agnosticism**: The headers contain NO program-type-specific
code. No `XDP_DROP`, no `TC_ACT_OK`, no `SEC("xdp")`. The only BPF
helper used is `bpf_tail_call()`, which is universal across all BPF
program types that support it.

---

## 4. Data Flow

### 4.1 Graph Setup (Userspace)

```
Application
    │
    ├─► egl_graph_create("name", max_nodes)
    │       └─► allocate struct, arrays, pin_dir
    │
    ├─► egl_graph_add_node(g, 0, "node_a.bpf.o", "prog_a")
    │       ├─► ensure_maps() ─► bpf_map_create(PROG_ARRAY)
    │       │                  ─► bpf_map_create(PERCPU_ARRAY)
    │       │                  ─► bpf_obj_pin() (both maps)
    │       ├─► bpf_object__open("node_a.bpf.o")
    │       ├─► bpf_map__reuse_fd() (share prog_array + stats)
    │       ├─► bpf_object__load()
    │       └─► bpf_map_update_elem(prog_array, 0, prog_fd)
    │
    ├─► egl_graph_add_edge(g, 0, 1)  // for DAG tracking
    │
    ├─► egl_graph_validate_dag(g)  // returns 0 or -ELOOP
    │
    └─► [Application attaches node 0 as XDP/TC/etc.]
```

### 4.2 Packet Processing (BPF / Kernel)

```
Packet arrives at NIC
    │
    ▼
Node 0 (entry) ──── SEC("tc") or SEC("xdp") ───────┐
    │                                              │
    ├─► EGL_STATS_INC_IN(egl_node_stats, 0, len)   │
    ├─► [node-specific processing]                 │
    ├─► EGL_STATS_INC_OUT(egl_node_stats, 0, len)  │
    ├─► EGL_NEXT(ctx, egl_prog_array, 1) ──────────┤
    │       │                                      │
    │       ▼                                      │
    │   Node 1 ──── same pattern ────────────────┐ │
    │       │                                    │ │
    │       ▼                                    │ │
    │   Node 2 (terminal) ──── returns action ◄──┘ │
    │                                              │
    └─── fall-through if tail call fails ◄─────────┘
```

### 4.3 Statistics Read (Userspace)

```
Application
    │
    ├─► egl_stats_read(g, node_id, &stats)
    │       ├─► libbpf_num_possible_cpus()
    │       ├─► bpf_map_lookup_elem(stats_fd, &key, percpu[])
    │       └─► aggregate: sum percpu[0..N] into stats
    │
    └─► stats.in_count, stats.out_count, stats.drops, ...
```

---

## 5. Interface Specification

### 5.1 External Interfaces

| Interface | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `egl_graph_*` API | App → Library | C function calls | Graph lifecycle management |
| `egl_loader_*` API | App → Library | C function calls | BPF object loading |
| `egl_reconfig_*` API | App → Library | C function calls | Staged reconfiguration |
| `egl_stats_*` API | App → Library | C function calls | Statistics aggregation |
| BPF maps (PROG_ARRAY) | Library → Kernel | BPF syscall | Tail-call dispatch table |
| BPF maps (PERCPU_ARRAY) | Library ↔ Kernel | BPF syscall | Per-node statistics |
| bpffs pin paths | Library → Filesystem | File I/O | Map sharing via `/sys/fs/bpf/egl/<name>/` |

### 5.2 Internal Interfaces

| Interface | From | To | Description |
|-----------|------|----|-------------|
| `ensure_maps()` | egl_graph | Kernel | Lazy map creation on first `add_node` |
| `bpf_map__reuse_fd()` | egl_graph | libbpf | Map sharing during node loading |
| `g_reconfig` global | egl_reconfig | egl_graph | Staging area; calls `add_node`/`remove_node` on commit |

---

## 6. Error Handling Strategy

### 6.1 Error Propagation

All public functions follow the same pattern:

```c
int egl_function(args...)
{
    if (invalid_args) { return -EINVAL; }
    if (resource_missing) { return -ENOENT; }

    ret = kernel_or_library_call();
    if (ret < 0) { cleanup(); return -errno; }

    return 0;  // success
}
```

**Convention**: Negative errno on error, 0 on success, pointer with
NULL on allocation failure.

### 6.2 Error Categories

| Category | Errno | Meaning | Caller Action |
|----------|-------|---------|---------------|
| Invalid argument | EINVAL | NULL pointer, out-of-range index | Fix caller code |
| Resource missing | ENOENT | Node not loaded, program not found | Load the resource first |
| Already exists | EEXIST | Node already at index | Remove first, then add |
| Busy | EBUSY | Reconfig already in progress | Wait or abort existing |
| Out of memory | ENOMEM | calloc/strdup failed | Retry or reduce load |
| Cycle detected | ELOOP | Graph has a directed cycle | Remove the offending edge |
| No space | ENOSPC | Staging area full (64 entries) | Commit current, begin new |

### 6.3 Cleanup Strategy

Resource cleanup uses the **goto chain** pattern:

```c
struct egl_graph *egl_graph_create(...)
{
    g = calloc(...);            if (!g) goto err_name;
    g->name = strdup(...);      if (!name) goto err_name;
    g->node_objs = calloc(...); if (!objs) goto err_objs;
    g->node_fds = calloc(...);  if (!fds) goto err_fds;
    g->edges = calloc(...);     if (!edges) goto err_edges;
    g->pin_dir = strdup(...);   if (!pin) goto err_pin;
    return g;

err_pin:    free(g->edges);
err_edges:  free(g->node_fds);
err_fds:    free(g->node_objs);
err_objs:   free(g->name);
err_name:   free(g);
            return NULL;
}
```

This ensures no resource leaks on any allocation failure path.

---

## 7. Safety Mechanisms

| Mechanism | Component | Protection Against |
|-----------|-----------|-------------------|
| Kahn's algorithm + CBMC proof | egl_graph | Cycle in graph topology (TE-1) |
| `MAX_TAIL_CALL_CNT` (kernel) | Linux BPF | Infinite loop even if cycle exists |
| `EGL_DEPTH_EXCEEDED` (optional) | egl_node.h | Early termination before kernel limit |
| Opaque struct (information hiding) | egl_graph | Direct state manipulation by caller |
| Global reconfig serialization | egl_reconfig | Concurrent reconfig race conditions |
| RCU grace period (10ms) | egl_reconfig | In-flight packets during reconfiguration |
| Map pinning with graph name | egl_graph | Cross-graph map collision |
| Negative errno on all errors | All components | Silent failure / undefined behavior |
| NULL checks on all public APIs | All components | Null pointer dereference |

---

## 8. Thread Safety

The library is **single-threaded by design**. No internal locking
is used. This is a deliberate choice for FuSa — mutexes add
complexity, failure modes, and priority inversion risks.

| Component | Thread Safety | Notes |
|-----------|:---:|-------|
| `egl_graph` (same instance) | **No** | Concurrent mutation corrupts adjacency matrix and node arrays |
| `egl_graph` (different instances) | **Yes** | Independent memory, no shared state |
| `egl_graph` (read-only, same instance) | **Yes** | `validate_dag`, `get_*_fd` can be concurrent with each other |
| `egl_reconfig` | **No** | Global staging area — one transaction system-wide |
| `egl_loader` (different handles) | **Yes** | Independent libbpf objects |
| `egl_stats_read` | **Yes** | Read-only map access; kernel handles per-CPU atomicity |
| BPF-side macros | **Yes** | Per-CPU maps; eBPF is non-preemptible on a single core |

**Caller responsibility**: All graph mutation and reconfiguration
must be serialized externally (e.g., single control-plane thread,
mutex). Stats reads and DAG validation may be called from any thread.

---

## 9. Design Constraints


| Constraint | Rationale |
|-----------|-----------|
| Pure C11 | FuSa certification; no C++ runtime dependencies |
| No program-type-specific code | Library is generic infrastructure; XDP/TC/etc. belong in downstream libraries |
| No GNU extensions (except `__attribute__`) | Portability; MISRA C:2012 alignment |
| Static library only | No dynamic loading complexity; deterministic linking |
| libbpf as sole BPF dependency | Canonical BPF library; minimizes qualification scope |
| Configurable graph size | Avoid hardcoded limits; support diverse deployment scales |

---

## 10. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Reconfig staging scope | Global (one transaction system-wide) | Simpler than per-graph; avoids per-graph allocation; serialization prevents races |
| Map creation | `ensure_maps()` creates maps with correct size on first `add_node` | Simpler than modifying BPF object map sizes via `bpf_map__set_max_entries` before load |
| `egl_graph_add_node` loading | Integrates BPF loading directly | `egl_loader` API exists for standalone use; graph API integrates loading for convenience |
| No internal locking | Caller serializes externally | FuSa: mutexes add complexity, failure modes, and priority inversion risks |
| Static library only | No `libegl.so` | Deterministic linking; no dynamic loading complexity; simpler qualification |
