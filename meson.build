# SPDX-License-Identifier: BSD-2-Clause
# ebpf-graph-lib — Generic eBPF graph processing library

project('ebpf-graph-lib', 'c',
    version: '0.1.0',
    license: 'BSD-2-Clause',
    default_options: [
        'c_std=c11',
        'warning_level=3',
        'buildtype=debug',
        'werror=true',
    ],
    meson_version: '>=0.56.0',
)

cc = meson.get_compiler('c')

# Warning flags matching project conventions
warning_flags = [
    '-Wall',
    '-Wextra',
    '-Werror',
    '-Wconversion',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
]

add_project_arguments(cc.get_supported_arguments(warning_flags), language: 'c')

# Dependencies
libbpf_dep = dependency('libbpf', version: '>=1.0')
libelf_dep = dependency('libelf')

egl_inc = include_directories('include')

# Public headers
egl_headers = files(
    'include/egl/egl_types.h',
    'include/egl/egl_node.h',
    'include/egl/egl_edge.h',
    'include/egl/egl_stats.h',
    'include/egl/egl_graph.h',
    'include/egl/egl_loader.h',
    'include/egl/egl_reconfig.h',
)

install_headers(egl_headers, subdir: 'egl')

# BPF common header — public API for BPF node programs.
# Lives under include/egl/bpf/ so it resolves via -I<include>.
install_headers('include/egl/bpf/egl_common.bpf.h', subdir: 'egl/bpf')

# Userspace static library
egl_lib = static_library('egl',
    'src/userspace/egl_graph.c',
    'src/userspace/egl_loader.c',
    'src/userspace/egl_stats.c',
    'src/userspace/egl_reconfig.c',
    include_directories: egl_inc,
    dependencies: [libbpf_dep, libelf_dep],
    install: true,
)

egl_dep = declare_dependency(
    link_with: egl_lib,
    include_directories: egl_inc,
    dependencies: [libbpf_dep],
)

# pkg-config file for downstream projects
pkg = import('pkgconfig')
pkg.generate(egl_lib,
    name: 'egl',
    description: 'Generic eBPF graph processing library',
    requires: ['libbpf'],
    subdirs: ['.'],
)

if get_option('enable_tests')
    subdir('tests')
endif

if get_option('enable_examples')
    subdir('examples')
endif

# Summary
summary({
    'Project': meson.project_name(),
    'Version': meson.project_version(),
    'C Standard': get_option('c_std'),
    'Build Type': get_option('buildtype'),
    'Tests': get_option('enable_tests'),
    'Examples': get_option('enable_examples'),
}, section: 'Configuration')
