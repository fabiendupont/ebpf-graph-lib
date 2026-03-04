#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Run CBMC inside a podman container with CPU and memory limits.
# CBMC and goto-cc are statically linked, so we bind-mount them directly.
#
# Usage: ./run-cbmc.sh [cbmc args...]
# Example:
#   ./run-cbmc.sh dag_cycle_harness.c ../../src/userspace/egl_graph.c \
#     -I ../../include --unwind 10 --bounds-check --pointer-check \
#     -DHARNESS_MAX_NODES=4 --object-bits 12
#
# Resource limits (override via environment):
#   CBMC_CPUS    - CPU limit (default: 4)
#   CBMC_MEMORY  - Memory limit (default: 16g)
#   CBMC_TIMEOUT - Timeout in minutes (default: 20)

set -euo pipefail

CBMC_CPUS="${CBMC_CPUS:-4}"
CBMC_MEMORY="${CBMC_MEMORY:-16g}"
CBMC_TIMEOUT="${CBMC_TIMEOUT:-20}"

CBMC_BIN="$HOME/.cargo/bin/cbmc"
GOTO_CC_BIN="$HOME/.cargo/bin/goto-cc"
GOTO_ANALYZER_BIN="$HOME/.cargo/bin/goto-analyzer"
GOTO_INSTRUMENT_BIN="$HOME/.cargo/bin/goto-instrument"

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

exec podman run --rm \
    --cpus="$CBMC_CPUS" \
    --memory="$CBMC_MEMORY" \
    --timeout="$((CBMC_TIMEOUT * 60))" \
    --network=none \
    --security-opt label=disable \
    -v "$CBMC_BIN:/usr/local/bin/cbmc:ro" \
    -v "$GOTO_CC_BIN:/usr/local/bin/goto-cc:ro" \
    -v "$GOTO_ANALYZER_BIN:/usr/local/bin/goto-analyzer:ro" \
    -v "$GOTO_INSTRUMENT_BIN:/usr/local/bin/goto-instrument:ro" \
    -v "$PROJECT_ROOT:/work:ro" \
    -w /work/verification/cbmc \
    localhost/cbmc-runner:latest \
    cbmc "$@"
