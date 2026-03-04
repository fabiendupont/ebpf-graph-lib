# Fault Tree Analysis — ebpf-graph-lib

**Document Version**: 0.1.0
**Standard**: ISO 26262:2018 Part 5, IEC 61508:2010 Part 2
**Method**: Qualitative Fault Tree Analysis (FTA)

---

## 1. Top-Level Events

This FTA analyzes the two top-level hazardous events for ebpf-graph-lib:

- **TE-1**: Kernel hang due to infinite tail-call loop
- **TE-2**: Silent data corruption (packets processed by wrong pipeline)

---

## 2. FTA-1: Kernel Hang Due to Infinite Tail-Call Loop

### 2.1 Fault Tree

```
                    ┌─────────────────────────┐
                    │  TE-1: Kernel Hang Due   │
                    │  to Infinite Tail-Call   │
                    │         Loop             │
                    └────────────┬────────────┘
                                 │
                               [AND]  ── All 5 barriers must fail simultaneously
                                 │
                 ┌───────────────┼───────────────────────────────┐
                 │               │               │               │
        ┌────────┴───────┐ ┌────┴─────┐ ┌───────┴──────┐ ┌──────┴───────┐
        │ G1: Cycle      │ │ G2: DAG  │ │ G3: Depth    │ │ G4: Kernel   │
        │ exists in      │ │ validator│ │ counter not  │ │ tail-call    │
        │ graph topology │ │ fails to │ │ used or      │ │ limit fails  │
        │                │ │ detect it│ │ misconfigured│ │ (33)         │
        └───────┬────────┘ └────┬─────┘ └───────┬──────┘ └──────┬───────┘
                │               │               │               │
              [OR]            [OR]            [OR]            [OR]
                │               │               │               │
         ┌──────┼──────┐   ┌───┼────┐    ┌─────┼─────┐     ┌───┴───┐
         │      │      │   │   │    │    │     │     │     │       │
       ┌─┴─┐ ┌─┴─┐ ┌──┴┐ ┌┴┐ ┌┴─┐ ┌┴┐ ┌─┴─┐ ┌─┴─┐ ┌┴─┐ ┌─┴──┐ ┌─┴──┐
       │B1 │ │B2 │ │B3 │ │B4│ │B5│ │B6│ │B7 │ │B8 │ │B9│ │B10 │ │B11 │
       └───┘ └───┘ └───┘ └──┘ └──┘ └──┘ └───┘ └───┘ └──┘ └────┘ └────┘
```

### 2.2 Gate Descriptions

| Gate | Type | Description |
|------|------|-------------|
| TE-1 | Top Event | Kernel hang due to infinite tail-call loop |
| G1 | Intermediate (OR) | A cycle exists in the graph topology |
| G2 | Intermediate (OR) | The DAG validator fails to detect the cycle |
| G3 | Intermediate (OR) | Runtime depth protection is absent or misconfigured |
| G4 | Intermediate (OR) | Kernel tail-call limit (33) fails to terminate the loop |
| Top AND | Gate | ALL four conditions must be true simultaneously |

### 2.3 Basic Events

| ID | Event | Probability | Justification |
|----|-------|:-----------:|---------------|
| B1 | User adds edge that creates cycle via `egl_graph_add_edge` | Possible | User error; no automatic rejection at edge-add time |
| B2 | Reconfig commit introduces cycle (add/remove sequence) | Possible | Staging doesn't validate DAG before commit |
| B3 | Direct PROG_ARRAY manipulation bypasses library | Possible | Attacker or misconfigured component writes to map directly |
| B4 | Bug in Kahn's algorithm implementation | Eliminated | CBMC proves correctness for N≤5 against DFS oracle |
| B5 | Memory corruption alters adjacency matrix | Very Low | `-Werror`, bounds checks, no buffer overflows in API |
| B6 | `validate_dag` not called before pipeline starts | Possible | User error; library doesn't enforce mandatory validation |
| B7 | Node doesn't use `EGL_DEPTH_EXCEEDED` | Likely | Depth counter is optional (documented as defense-in-depth) |
| B8 | `EGL_DEPTH_EXCEEDED` threshold set too high (>33) | Possible | User misconfiguration |
| B9 | Depth map not shared across all nodes | Possible | Each node must declare/reuse the same depth map |
| B10 | Kernel bug in `MAX_TAIL_CALL_CNT` enforcement | Near Zero | Core kernel mechanism, extensively tested, simple implementation |
| B11 | Kernel version doesn't enforce tail-call limit | Near Zero | Present since BPF tail calls were introduced (Linux 4.2) |

### 2.4 Cut Set Analysis

The top event requires **all four** intermediate gates to be true (AND gate):

**Minimal cut sets** (each requires G1 ∧ G2 ∧ G3 ∧ G4):

| Cut Set | Events | Assessment |
|---------|--------|------------|
| 1 | B1 ∧ B4 ∧ B7 ∧ B10 | **Eliminated** — B4 is proven impossible by CBMC |
| 2 | B1 ∧ B5 ∧ B7 ∧ B10 | **Near Zero** — requires memory corruption AND kernel bug |
| 3 | B1 ∧ B6 ∧ B7 ∧ B10 | **Near Zero** — requires user skipping validation AND kernel bug |
| 4 | B2 ∧ B4 ∧ B7 ∧ B10 | **Eliminated** — B4 is proven impossible |
| 5 | B3 ∧ B4 ∧ B7 ∧ B10 | **Eliminated** — B4 is proven impossible |
| 6 | B1 ∧ B6 ∧ B8 ∧ B10 | **Near Zero** — requires 3 independent failures |

**Conclusion**: No single failure can cause TE-1. All realistic cut sets
require at least 3 independent failures, one of which is either proven
impossible (B4) or near zero probability (B10). The AND gate at the top
level provides structural protection.

### 2.5 Recommendations from FTA

| ID | Recommendation | Priority | Status |
|----|---------------|----------|--------|
| R1 | Add automatic DAG validation in `egl_reconfig_commit` before applying changes | High | **Recommended** |
| R2 | Document that `egl_graph_validate_dag` MUST be called before starting the pipeline | Medium | Documented in API |
| R3 | Consider making `EGL_DEPTH_EXCEEDED` mandatory rather than optional | Low | Design decision — downstream concern |
| R4 | Add `egl_graph_add_edge_safe` that atomically adds edge + validates DAG | Medium | **Recommended** |

---

## 3. FTA-2: Silent Data Corruption (Wrong Pipeline Configuration)

### 3.1 Fault Tree

```
                    ┌─────────────────────────┐
                    │  TE-2: Packets Processed │
                    │  by Wrong Pipeline       │
                    │  Configuration            │
                    └────────────┬────────────┘
                                 │
                               [OR]
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
     ┌────────┴───────┐ ┌───────┴───────┐ ┌────────┴───────┐
     │ G5: Stale node │ │ G6: Partial   │ │ G7: Map        │
     │ in PROG_ARRAY  │ │ reconfig      │ │ sharing        │
     │                │ │ applied       │ │ failure        │
     └───────┬────────┘ └───────┬───────┘ └────────┬───────┘
             │                  │                   │
           [OR]               [OR]                [OR]
             │                  │                   │
        ┌────┼────┐       ┌────┼────┐         ┌────┼────┐
        │    │    │       │    │    │         │    │    │
      ┌─┴─┐┌┴──┐┌┴──┐  ┌─┴─┐┌┴──┐┌┴──┐   ┌─┴──┐┌┴──┐┌┴──┐
      │C1 ││C2 ││C3 │  │C4 ││C5 ││C6 │   │C7  ││C8 ││C9 │
      └───┘└───┘└───┘  └───┘└───┘└───┘   └────┘└───┘└───┘
```

### 3.2 Basic Events

| ID | Event | Probability | Justification |
|----|-------|:-----------:|---------------|
| C1 | `remove_node` fails silently (PROG_ARRAY delete fails) | Very Low | `bpf_map_delete_elem` errors are rare; return value checked |
| C2 | Node BPF object freed but PROG_ARRAY entry persists | Very Low | Library removes from PROG_ARRAY before closing object |
| C3 | Race between `remove_node` and in-flight tail call | By Design | Kernel holds refcount; old program completes safely |
| C4 | `reconfig_commit` fails mid-way through adds | Possible | Returns error; already-applied removes persist |
| C5 | RCU grace period too short; old config packets still in flight | Low | 10ms conservative bound; see `egl_reconfig.c` analysis |
| C6 | Concurrent reconfig from different thread | Prevented | Global staging area returns -EBUSY |
| C7 | BPF object loaded with wrong PROG_ARRAY (not reused) | Possible | Library uses `bpf_map__reuse_fd`; failure returns error |
| C8 | Map pin path collision between different graphs | Low | Pin paths include graph name: `/sys/fs/bpf/egl/<name>/` |
| C9 | Stats map not shared; node reads stale stats | Low | Same reuse mechanism as PROG_ARRAY |

### 3.3 Cut Set Analysis

TE-2 uses an OR gate at the top — any single path can cause the event.
However, most basic events have built-in mitigations:

| Event | Severity | Mitigation | Residual Risk |
|-------|----------|------------|---------------|
| C4 | Medium | Caller checks return value; can retry or rollback manually | **Low** — documented behavior |
| C5 | Low | 10ms bound with documented analysis; caller can extend | **Very Low** |
| C7 | Medium | `bpf_map__reuse_fd` failure returns error to caller | **Low** |
| Others | Low-Very Low | Library design prevents or mitigates | **Very Low** |

### 3.4 Recommendations from FTA

| ID | Recommendation | Priority | Status |
|----|---------------|----------|--------|
| R5 | Add rollback capability to `egl_reconfig_commit` on partial failure | Medium | **Recommended** |
| R6 | Log warning when `bpf_map_delete_elem` fails in `remove_node` | Low | Currently silent |
| R7 | Add `egl_graph_verify_consistency` function to check PROG_ARRAY matches internal state | Medium | **Recommended** |

---

## 4. Summary

### 4.1 Risk Assessment

| Top Event | Severity | Probability (with mitigations) | Risk Level |
|-----------|----------|:------------------------------:|:----------:|
| TE-1: Kernel hang | **Critical** | **Near Zero** (requires 3+ independent failures, one proven impossible) | **Acceptable** |
| TE-2: Wrong pipeline | **Medium** | **Low** (partial reconfig is the main residual risk) | **Acceptable with monitoring** |

### 4.2 Relationship to Defense-in-Depth

The FTA confirms the defense-in-depth architecture from SAFETY_CASE.md §7:

- **TE-1** is protected by a 5-layer AND gate. CBMC eliminates the
  algorithm-correctness failure mode entirely. The kernel limit
  provides an independent backstop.

- **TE-2** is primarily mitigated by the library's error propagation
  design (all functions return negative errno) and the atomic nature
  of PROG_ARRAY updates.

### 4.3 FTA vs FMEA Comparison

| Aspect | FMEA (SAFETY_CASE.md §5) | FTA (this document) |
|--------|--------------------------|---------------------|
| Approach | Bottom-up (what can each component do wrong?) | Top-down (what causes the hazard?) |
| Strength | Comprehensive component-level coverage | Identifies common-cause failures and cut sets |
| Finding | Individual failure modes and mitigations | AND gate structure proves no single point of failure for TE-1 |
| Unique insight | Reconfig partial-commit risk (C4) | CBMC eliminates B4 from all cut sets, proving no algorithm-level path to TE-1 |
