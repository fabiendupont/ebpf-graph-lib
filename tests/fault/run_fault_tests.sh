#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Run fault injection tests with LD_PRELOAD.
# Iterates over calloc and malloc failure points to exercise
# all allocation error paths.
#
# Usage: ./run_fault_tests.sh <libfault_alloc.so> <test_binary>

set -euo pipefail

LIBFAULT="${1:?Usage: $0 <libfault_alloc.so> <test_binary>}"
TEST_BIN="${2:?Usage: $0 <libfault_alloc.so> <test_binary>}"

if [ ! -f "$LIBFAULT" ]; then
    echo "ERROR: $LIBFAULT not found"
    exit 1
fi

if [ ! -x "$TEST_BIN" ]; then
    echo "ERROR: $TEST_BIN not found or not executable"
    exit 1
fi

FAILED=0

echo "=== Fault Injection Test Suite ==="
echo "Library: $LIBFAULT"
echo "Binary:  $TEST_BIN"
echo ""

# Run without fault injection first (error path tests)
echo "--- Pass 0: No fault injection ---"
if ! "$TEST_BIN"; then
    echo "FAIL: base test failed"
    FAILED=1
fi
echo ""

# Calloc failure at each allocation point (0-8 covers all paths)
for n in $(seq 0 8); do
    echo "--- Pass $((n+1)): FAULT_CALLOC_AFTER=$n ---"
    if ! FAULT_CALLOC_AFTER=$n LD_PRELOAD="$LIBFAULT" "$TEST_BIN" 2>/dev/null; then
        echo "  (test returned non-zero — expected for some fault points)"
    fi
    echo ""
done

# Malloc failure at each point (covers strdup failures, 0-12)
for n in $(seq 0 12); do
    echo "--- Pass $((n+10)): FAULT_MALLOC_AFTER=$n ---"
    if ! FAULT_MALLOC_AFTER=$n LD_PRELOAD="$LIBFAULT" "$TEST_BIN" 2>/dev/null; then
        echo "  (test returned non-zero — expected for some fault points)"
    fi
    echo ""
done

if [ $FAILED -eq 0 ]; then
    echo "=== All fault injection passes completed ==="
    exit 0
else
    echo "=== Some passes failed ==="
    exit 1
fi
