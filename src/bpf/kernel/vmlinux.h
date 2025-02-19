#ifndef __VMLINUX_PATCH_H__
#define __VMLINUX_PATCH_H__

#include "_vmlinux.h"

/**
 * These types must be properly aligned, otherwise BPF verification would fail.
 * They are commented out in "_vmlinux.h", originally generated with bpftool.
 */

struct bpf_timer {
    __u64 __opaque[2];
} __attribute__((aligned(8)));

#endif
