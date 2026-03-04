/* SPDX-License-Identifier: BSD-2-Clause */

#define _POSIX_C_SOURCE 200809L

#include <egl/egl_loader.h>
#include <egl/egl_types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

struct egl_bpf_prog {
    struct bpf_object *obj;
    char *obj_path;
};

struct egl_bpf_prog *egl_loader_open(const char *obj_path)
{
    struct egl_bpf_prog *prog;
    int ret;

    if (obj_path == NULL) { return NULL; }

    prog = calloc(1, sizeof(*prog));
    if (prog == NULL) { return NULL; }

    prog->obj_path = strdup(obj_path);
    if (prog->obj_path == NULL) {
        free(prog);
        return NULL;
    }

    prog->obj = bpf_object__open(obj_path);
    if (prog->obj == NULL) {
        free(prog->obj_path);
        free(prog);
        return NULL;
    }

    ret = bpf_object__load(prog->obj);
    if (ret < 0) {
        bpf_object__close(prog->obj);
        free(prog->obj_path);
        free(prog);
        return NULL;
    }

    return prog;
}

int egl_loader_get_prog_fd(struct egl_bpf_prog *prog, const char *name)
{
    struct bpf_program *p;

    if (prog == NULL || name == NULL) { return -EINVAL; }

    p = bpf_object__find_program_by_name(prog->obj, name);
    if (p == NULL) { return -ENOENT; }

    return bpf_program__fd(p);
}

int egl_loader_get_prog_type(struct egl_bpf_prog *prog, const char *name)
{
    struct bpf_program *p;

    if (prog == NULL || name == NULL) { return -EINVAL; }

    p = bpf_object__find_program_by_name(prog->obj, name);
    if (p == NULL) { return -ENOENT; }

    return (int)bpf_program__type(p);
}

static int make_dir_recursive(const char *path)
{
    char tmp[256];
    char *p;
    int ret;

    (void)snprintf(tmp, sizeof(tmp), "%s", path);

    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            ret = mkdir(tmp, 0755);
            if (ret < 0 && errno != EEXIST) { return -errno; }
            *p = '/';
        }
    }

    ret = mkdir(tmp, 0755);
    if (ret < 0 && errno != EEXIST) { return -errno; }

    return 0;
}

int egl_loader_pin_maps(struct egl_bpf_prog *prog, const char *pin_dir)
{
    struct bpf_map *map;
    int ret;

    if (prog == NULL || pin_dir == NULL) { return -EINVAL; }

    ret = make_dir_recursive(pin_dir);
    if (ret < 0) { return ret; }

    bpf_object__for_each_map(map, prog->obj) {
        char path[512];

        (void)snprintf(path, sizeof(path), "%s/%s",
                       pin_dir, bpf_map__name(map));

        ret = bpf_map__pin(map, path);
        if (ret < 0 && ret != -EEXIST) { return ret; }
    }

    return 0;
}

int egl_loader_reuse_maps(struct egl_bpf_prog *prog, const char *pin_dir)
{
    struct bpf_map *map;

    if (prog == NULL || pin_dir == NULL) { return -EINVAL; }

    bpf_object__for_each_map(map, prog->obj) {
        char path[512];
        int fd;

        (void)snprintf(path, sizeof(path), "%s/%s",
                       pin_dir, bpf_map__name(map));

        fd = bpf_obj_get(path);
        if (fd >= 0) {
            int ret = bpf_map__reuse_fd(map, fd);
            close(fd);
            if (ret < 0) { return ret; }
        }
    }

    return 0;
}

void egl_loader_close(struct egl_bpf_prog *prog)
{
    if (prog == NULL) { return; }

    if (prog->obj != NULL) {
        bpf_object__close(prog->obj);
    }

    free(prog->obj_path);
    free(prog);
}
