// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

#include "kernel/bpf_ct.h"
#include "kernel/bpf_experimental.h"
#include "kernel/vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_log.h"

// #include <linux/if_ether.h>
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

// #include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define AF_INET 2
#define AF_INET6 10

enum {
    NAT_FILTERING_INDEPENDENT = 0, // Endpoint-Independent Filtering
    NAT_FILTERING_DEST_ADDRESS,    // Address-Dependent Filtering
};

union u_inet_addr {
    __u32 all[4];
    __be32 ip;
    __be32 ip6[4];
};

struct inet_tuple {
    union u_inet_addr saddr;
    union u_inet_addr daddr;
    __be16 sport;
    __be16 dport;
};

struct map_ext_to_intern_key {
    u32 ifindex;
    u8 is_ipv4;
    u8 l4proto;
    // ICMP ID in the case of ICMP
    __be16 ext_port;
    union u_inet_addr ext_addr;
};

struct map_ext_to_intern_value {
    // original tuple from internal to destination perspective
    struct inet_tuple origin;
};

// XXX: Does this necessary? We can always get the external address
// struct map_intern_to_ext_key {
//     u32 ifindex;
//     u8 is_ipv4;
//     u8 l4proto;
//     // internal source
//     __be16 src_port;
//     union u_inet_addr src_addr;
// };

// struct map_intern_to_ext_value {
//     // SNATed tuple from external to destination perspective
//     struct inet_tuple external;
// };

struct map_frag_track_key {
    u32 ifindex;
    u8 is_ipv4;
    u8 l4proto;
    __be16 id;
    union u_inet_addr saddr;
    union u_inet_addr daddr;
};

struct map_frag_track_value {
    __be16 sport;
    __be16 dport;
};

struct mapping_key {
    // SNAT external source addr & port
    union u_inet_addr ext_addr;
    // destination address for "Address-Dependent Filtering", 0 if in
    // "Endpoint-Independent Filtering" mode
    union u_inet_addr dest_addr;
    // interface this mapping associated with
    u32 ifindex;
    __be16 ext_port;
    bool is_ipv4;
};

struct mapping_origin {
    struct inet_tuple orig_tuple;
    struct bpf_list_node node;
};

struct mapping_value {
    // internal source addr & port
    union u_inet_addr orig_addr;
    __be16 orig_port;

    // struct bpf_timer refresh_timer;

    // NOTE: It's not well documented but bpf_{list_head, rb_node} requires
    // using bpf_spin_lock, see
    // https://github.com/torvalds/linux/blob/5254c0cbc92d2a08e75443bdb914f1c4839cdf5a/kernel/bpf/btf.c#L3820-L3825
    struct bpf_spin_lock lock;
    struct bpf_list_head origin_list_head __contains(mapping_origin, node);
    u32 len;
};

struct conn_key {
    struct inet_tuple origin;
    struct mapping_key key;
};

struct conn_value {
    u8 _placeholder;
};

#define private(name) SEC(".bss." #name) __hidden

#define COPY_ADDR6(t, s) (__builtin_memcpy((t), (s), sizeof(t)))

static inline __attribute__((always_inline)) void
inet_tuple_copy(struct inet_tuple *t1, const struct inet_tuple *t2) {

    COPY_ADDR6(t1->saddr.all, t2->saddr.all);
    COPY_ADDR6(t1->daddr.all, t2->daddr.all);
    t1->sport = t2->sport;
    t1->dport = t2->dport;
}

static inline __attribute__((always_inline)) void
inet_tuple_parse_nf(struct inet_tuple *t, const struct nf_conntrack_tuple *t2) {
    COPY_ADDR6(t->saddr.all, t2->src.u3.all);
    COPY_ADDR6(t->daddr.all, t2->dst.u3.all);
    t->sport = t2->src.u.all;
    t->dport = t2->dst.u.all;
}

static inline __attribute__((always_inline)) void
bpf_sock_tuple_parse(struct bpf_sock_tuple *t, bool is_ipv4,
                     const struct inet_tuple *t2) {
    if (is_ipv4) {
        t->ipv4.saddr = t2->saddr.ip;
        t->ipv4.daddr = t2->daddr.ip;
        t->ipv4.sport = t2->sport;
        t->ipv4.dport = t2->dport;
    } else {
        COPY_ADDR6(t->ipv6.saddr, t2->saddr.ip6);
        COPY_ADDR6(t->ipv6.daddr, t2->daddr.ip6);
        t->ipv6.sport = t2->sport;
        t->ipv6.dport = t2->dport;
    }
}

static inline __attribute__((always_inline)) void
mapping_key_copy(struct mapping_key *k, const struct mapping_key *k2) {

    k->ifindex = k2->ifindex;
    k->is_ipv4 = k2->is_ipv4;
    k->ext_port = k2->ext_port;
    COPY_ADDR6(k->ext_addr.all, k2->ext_addr.all);
    COPY_ADDR6(k->dest_addr.all, k2->dest_addr.all);
}

static inline __attribute__((always_inline)) void
conn_key_parse(struct conn_key *c_key, const struct mapping_key *m_key,
               const struct inet_tuple *tuple) {
    mapping_key_copy(&c_key->key, m_key);
    inet_tuple_copy(&c_key->origin, tuple);
}
