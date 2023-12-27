// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

#include "kernel/vmlinux.h"
#include "kernel/bpf_ct.h"
#include "kernel/bpf_experimental.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// #include <linux/if_ether.h>
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

// #include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct inet_tuple {
    union nf_inet_addr saddr;
    __be16 sport;
    union nf_inet_addr daddr;
    __be16 dport;
};

struct mapping_key {
    // interface this mapping associated with
    u32 ifindex;
    // SNAT external source addr & port
    union nf_inet_addr ext_addr;
    __be16 ext_port;
};

struct mapping_origin {
    struct nf_conntrack_tuple orig_tuple;
    struct bpf_list_node node;
};

struct mapping_value {
    struct mapping_key key;
    bool is_ipv4;
    // internal source addr & port
    union nf_inet_addr orig_addr;
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
    struct mapping_key m_key;
};

struct conn_value {
    u8 _placeholder;
};

#define private(name) SEC(".bss." #name) __hidden

static inline void nf_inet_addr_copy(union nf_inet_addr *a1,
                                     const union nf_inet_addr *a2) {
    a1->all[0] = a2->all[0];
    a1->all[1] = a2->all[1];
    a1->all[2] = a2->all[2];
    a1->all[3] = a2->all[3];
}

static inline void nf_ct_tuple_copy(struct nf_conntrack_tuple *t1,
                                    const struct nf_conntrack_tuple *t2) {
    nf_inet_addr_copy(&t1->src.u3, &t2->src.u3);
    nf_inet_addr_copy(&t1->dst.u3, &t2->dst.u3);
    t1->src.u.all = t2->src.u.all;
    t1->dst.u.all = t2->dst.u.all;
    t1->src.l3num = t2->src.l3num;
    t1->dst.protonum = t2->dst.protonum;
    t1->dst.dir = t2->dst.dir;
}

static inline void bpf_sock_tuple_parse(struct bpf_sock_tuple *t, bool is_ipv4,
                                        const struct nf_conntrack_tuple *nf_t) {
    __be16 sport = nf_t->src.u.all;
    __be16 dport = nf_t->dst.u.all;
    if (is_ipv4) {
        t->ipv4.saddr = nf_t->src.u3.ip;
        t->ipv4.daddr = nf_t->dst.u3.ip;
        t->ipv4.sport = sport;
        t->ipv4.dport = dport;
    } else {
        __builtin_memcpy(t->ipv6.saddr, nf_t->src.u3.ip6,
                         sizeof(t->ipv6.saddr));
        __builtin_memcpy(t->ipv6.daddr, nf_t->dst.u3.ip6,
                         sizeof(t->ipv6.daddr));
        t->ipv4.sport = sport;
        t->ipv4.dport = dport;
    }
}
