#ifndef __VMLINUX_PATCH_H__
#define __VMLINUX_PATCH_H__

#include "_vmlinux.h"

/*
 *	NextHeader field of IPv6 header
 */

#define NEXTHDR_HOP 0        /* Hop-by-hop option header. */
#define NEXTHDR_IPV4 4       /* IPv4 in IPv6 */
#define NEXTHDR_TCP 6        /* TCP segment. */
#define NEXTHDR_UDP 17       /* UDP message. */
#define NEXTHDR_IPV6 41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING 43   /* Routing header. */
#define NEXTHDR_FRAGMENT 44  /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE 47       /* GRE header. */
#define NEXTHDR_ESP 50       /* Encapsulating security payload. */
#define NEXTHDR_AUTH 51      /* Authentication header. */
#define NEXTHDR_ICMP 58      /* ICMP for IPv6. */
#define NEXTHDR_NONE 59      /* No next header */
#define NEXTHDR_DEST 60      /* Destination options header. */
#define NEXTHDR_SCTP 132     /* SCTP message. */
#define NEXTHDR_MOBILITY 135 /* Mobility header. */

#define NEXTHDR_MAX 255

/**
 * These types must be properly aligned, otherwise BPF verification would fail.
 * They are commented out in "_vmlinux.h", originally generated with bpftool.
 */

struct bpf_timer {
    __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_dynptr {
    __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_list_head {
    __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_list_node {
    __u64 __opaque[3];
} __attribute__((aligned(8)));

struct bpf_rb_root {
    __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_rb_node {
    __u64 __opaque[4];
} __attribute__((aligned(8)));

struct bpf_refcount {
    __u32 __opaque[1];
} __attribute__((aligned(4)));

struct bpf_iter_num {
    __u64 __opaque[1];
} __attribute__((aligned(8)));

#endif
