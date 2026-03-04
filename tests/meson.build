# SPDX-License-Identifier: BSD-2-Clause
# Test build definitions

# Unit tests — pure userspace, no BPF loading required
test_dag = executable('test_dag',
    'unit/test_dag.c',
    include_directories: egl_inc,
    link_with: egl_lib,
    dependencies: [libbpf_dep],
)

test('dag', test_dag, timeout: 30)

test_graph = executable('test_graph',
    'unit/test_graph.c',
    include_directories: egl_inc,
    link_with: egl_lib,
    dependencies: [libbpf_dep],
)

test('graph', test_graph, timeout: 30)

test_stats = executable('test_stats',
    'unit/test_stats.c',
    include_directories: egl_inc,
    link_with: egl_lib,
    dependencies: [libbpf_dep],
)

test('stats', test_stats, timeout: 30)

# Integration tests
test_tc = executable('test_tc_pipeline',
    'integration/test_tc_pipeline.c',
    include_directories: egl_inc,
    link_with: egl_lib,
    dependencies: [libbpf_dep],
)

test('tc_pipeline', test_tc, timeout: 60)

# Fault injection tests
dl_dep = cc.find_library('dl', required: true)

libfault_alloc = shared_library('fault_alloc',
    'fault/libfault_alloc.c',
    dependencies: [dl_dep],
    c_args: ['-Wno-missing-prototypes', '-Wno-strict-prototypes', '-Wno-pedantic'],
)

test_fault = executable('test_fault_alloc',
    'fault/test_fault_alloc.c',
    include_directories: egl_inc,
    link_with: egl_lib,
    dependencies: [libbpf_dep],
)

test('fault_alloc', test_fault, timeout: 30)
