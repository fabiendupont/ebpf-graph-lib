/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef EGL_LOADER_H
#define EGL_LOADER_H

struct egl_bpf_prog;

/* Load a BPF object file using libbpf CO-RE */
struct egl_bpf_prog *egl_loader_open(const char *obj_path);

/* Find a program by name within the loaded object */
int egl_loader_get_prog_fd(struct egl_bpf_prog *prog, const char *name);

/* Get program type (BPF_PROG_TYPE_XDP, BPF_PROG_TYPE_SCHED_CLS, etc.) */
int egl_loader_get_prog_type(struct egl_bpf_prog *prog, const char *name);

/* Pin maps for sharing between BPF objects */
int egl_loader_pin_maps(struct egl_bpf_prog *prog, const char *pin_dir);

/* Reuse pinned maps from another loaded object */
int egl_loader_reuse_maps(struct egl_bpf_prog *prog, const char *pin_dir);

/* Close and free */
void egl_loader_close(struct egl_bpf_prog *prog);

#endif /* EGL_LOADER_H */
