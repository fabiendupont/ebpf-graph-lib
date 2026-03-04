# Configuration Management Plan — ebpf-graph-lib

**Document Version**: 0.1.0
**Standard**: ISO 26262:2018 Part 8, §7 (Configuration Management)

---

## 1. Scope

This plan covers configuration management for ebpf-graph-lib source
code, build artifacts, verification evidence, and documentation.

**Configuration items under control**:
- Source code (`src/`, `include/`, `tests/`, `examples/`)
- Build system (`meson.build`, `meson_options.txt`, `subprojects/`)
- Verification artifacts (`verification/cbmc/`, `verification/tlaplus/`, `verification/fta/`)
- Safety documentation (`SAFETY_CASE.md`, `ARCHITECTURE.md`, `CM_PLAN.md`, `SPEC.md`)
- CI/CD configuration (`.gitlab-ci.yml`)

---

## 2. Version Control

### 2.1 Repository

- **System**: Git
- **Host**: GitHub (github.com)
- **Repository**: `smgglrs/ebpf-graph-lib`

### 2.2 Branching Strategy

```
main ─────────────────────────────────────────────────►
  │                                          ▲
  ├── feature/add-depth-counter ─────────────┤  (MR)
  │                                          │
  ├── fix/reconfig-rollback ─────────────────┤  (MR)
  │                                          │
  └── release/v0.1.0 ── tag: v0.1.0         │
```

| Branch | Purpose | Merge Target | CI |
|--------|---------|:------------:|:--:|
| `main` | Stable, verified code | — | Build + test only |
| `feature/*` | New functionality | `main` via MR | Full pipeline |
| `fix/*` | Bug fixes | `main` via MR | Full pipeline |
| `release/*` | Release preparation | `main` via MR + tag | Full pipeline |

### 2.3 Merge Request Requirements

Every merge request into `main` MUST:

1. Pass all CI pipeline jobs (build, analyze, verify, test, coverage)
2. Have at least one reviewer approval
3. Have no unresolved cppcheck errors
4. Have all CBMC proofs passing
5. Have TLA+ model checking passing
6. Not decrease code coverage below 95% line / 85% branch

### 2.4 Commit Message Convention

```
<type>: <short description>

<body — what and why>

Signed-off-by: Name <email>
```

Types: `feat`, `fix`, `refactor`, `test`, `verify`, `doc`, `ci`, `build`

---

## 3. Version Numbering

Semantic Versioning 2.0.0: `MAJOR.MINOR.PATCH`

| Component | Increment When |
|-----------|---------------|
| MAJOR | Incompatible API change (function signature, struct layout) |
| MINOR | New functionality (backward compatible) |
| PATCH | Bug fix (backward compatible, no new features) |

**Current version**: 0.1.0 (pre-release; API may change)

**Version 1.0.0 criteria**: all SAFETY_CASE.md open items resolved,
CBMC proofs at N=5+ for all harnesses, 95%+ line and 85%+ branch
coverage including BPF loading paths, safety case reviewed by an
independent party.

Version is defined in `meson.build`:
```meson
project('ebpf-graph-lib', 'c', version: '0.1.0', ...)
```

---

## 4. Release Process

### 4.1 Steps

1. Create `release/vX.Y.Z` branch from `main`
2. Update version in `meson.build`
3. Update `SAFETY_CASE.md` document version
4. Run full verification suite (CBMC, TLA+, all tests, coverage)
5. Create merge request, get reviewer approval
6. Merge to `main`
7. Tag: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
8. Push tag: `git push origin vX.Y.Z`

### 4.2 Release Artifacts

Each release includes:
- Source tarball (`ebpf-graph-lib-X.Y.Z.tar.gz`)
- CBMC proof logs (N=3 CI + N=5 offline)
- TLA+ model checking log
- Coverage report (HTML + Cobertura XML)
- cppcheck analysis report

---

## 5. Dependency Management

### 5.1 Controlled Dependencies

| Dependency | Version | Pinning Mechanism | Qualification |
|-----------|---------|-------------------|---------------|
| libbpf | ≥1.0 | `subprojects/libbpf.wrap` | TCL2 / T2 |
| libelf | system | System package | N/A (standard) |
| GCC | 15.x | CI image `fedora:43` | TCL3 / T3 |
| Clang (BPF) | 21.x | CI image `fedora:43` | TCL3 / T3 |
| CBMC | 6.1.x | CI `dnf install cbmc` | TCL1 / T1 |
| TLA+/TLC | 1.8.0 | Pinned JAR URL in CI | TCL1 / T1 |

### 5.2 Dependency Update Policy

- **libbpf**: Update only with full re-verification (CBMC + TLA+ +
  integration tests). Document the version change in release notes.
- **Compiler (GCC/Clang)**: Update with CI image. Re-run all tests
  and CBMC proofs. For Clang BPF updates, perform bytecode translation
  validation on example programs.
- **CBMC**: Update freely (verification tool, TCL1).
- **TLA+**: Update freely (verification tool, TCL1).

---

## 6. Change Control

### 6.1 Change Categories

| Category | Approval | Verification Required |
|----------|----------|----------------------|
| **Safety-critical** (DAG validator, PROG_ARRAY ops, reconfig commit) | 2 reviewers | Full CBMC + TLA+ + integration |
| **High** (loader, stats, new API functions) | 1 reviewer | Unit tests + integration |
| **Medium** (documentation, CI, build system) | 1 reviewer | CI pipeline |
| **Low** (comments, formatting) | Self-merge allowed | CI pipeline |

### 6.2 Safety-Critical Files

Changes to these files require the full verification suite:

- `src/userspace/egl_graph.c` (DAG validator, node lifecycle)
- `src/userspace/egl_reconfig.c` (atomic reconfiguration)
- `include/egl/egl_node.h` (BPF node contract, depth counter)
- `include/egl/egl_edge.h` (PROG_ARRAY declaration)
- `verification/cbmc/*.c` (proof harnesses)
- `verification/tlaplus/*.tla` (formal specification)

---

## 7. Traceability

All changes are traceable via:

1. **Git commit history**: every change has a commit with type prefix
2. **Merge request**: links commit to review discussion
3. **CI pipeline**: links commit to build/test/verify results
4. **SAFETY_CASE.md §4**: links requirements to tests and proofs

For safety-critical changes, the merge request description MUST
reference the affected safety requirements (FSR-1 through FSR-10)
and confirm that the relevant verification evidence is updated.

---

## 8. Backup and Recovery

- **Primary**: GitHub server (github.com)
- **Developer clones**: each developer has a full repository clone
- **CI artifacts**: retained per `expire_in` settings (7-30 days)
- **Verification evidence**: CBMC and TLA+ logs archived with releases
