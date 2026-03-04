# SPDX-License-Identifier: BSD-2-Clause
# Example build definitions

# TC chain example — requires BPF objects to be compiled separately
tc_chain = executable('tc_chain',
    'tc_chain/tc_chain_main.c',
    include_directories: egl_inc,
    link_with: egl_lib,
    dependencies: [libbpf_dep],
)
