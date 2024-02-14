// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

#include "kernel/vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_log.h"

#ifndef FEAT_IPV6
// #define FEAT_IPV6
#endif

// #include <linux/if_ether.h>
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define IP_CE 0x8000     /* Flag: "Congestion"		*/
#define IP_DF 0x4000     /* Flag: "Don't Fragment"	*/
#define IP_MF 0x2000     /* Flag: "More Fragments"	*/
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part	*/

#define MAX_IPV6_EXT_NUM 6

/*
 *	NextHeader field of IPv6 header
 */

#define NEXTHDR_HOP 0       /* Hop-by-hop option header. */
#define NEXTHDR_ROUTING 43  /* Routing header. */
#define NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH 51     /* Authentication header. */
#define NEXTHDR_DEST 60     /* Destination options header. */

#define NEXTHDR_TCP 6    /* TCP segment. */
#define NEXTHDR_UDP 17   /* UDP message. */
#define NEXTHDR_ICMP 58  /* ICMP for IPv6. */
#define NEXTHDR_NONE 59  /* No next header */
#define NEXTHDR_SCTP 132 /* SCTP message. */

#define IPV6_FRAG_OFFSET 0xFFF8
#define IPV6_FRAG_MF 0x0001

// #include <linux/icmp.h>
#define ICMP_DEST_UNREACH 3   /* Destination Unreachable	*/
#define ICMP_TIME_EXCEEDED 11 /* Time Exceeded		*/
#define ICMP_PARAMETERPROB 12 /* Parameter Problem		*/

#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/

// #include <linux/icmpv6.h>
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG 2
#define ICMPV6_TIME_EXCEED 3
#define ICMPV6_PARAMPROB 4

#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

#define AF_INET 2
#define AF_INET6 10

#define CLOCK_MONOTONIC 1

// #include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define BPF_LOOP_RET_CONTINUE 0
#define BPF_LOOP_RET_BREAK 1

#define TC_SKB_L3_OFF (sizeof(struct ethhdr))

union u_inet_addr {
#ifdef FEAT_IPV6
    __u32 all[4];
    __be32 ip;
    __be32 ip6[4];
#else
    __u32 all[1];
    __be32 ip;
#endif
};

struct inet_tuple {
    union u_inet_addr saddr;
    union u_inet_addr daddr;
    __be16 sport;
    __be16 dport;
};

struct ipv4_lpm_key {
    u32 prefixlen;
    __be32 ip;
};

struct ipv6_lpm_key {
    u32 prefixlen;
    __be32 ip6[4];
};

struct port_range {
    u16 begin_port;
    u16 end_port;
};

#define MAX_PORT_RANGES 4

struct external_config {
    struct port_range tcp_range[MAX_PORT_RANGES];
    struct port_range udp_range[MAX_PORT_RANGES];
    struct port_range icmp_range[MAX_PORT_RANGES];
    u8 tcp_range_len;
    u8 udp_range_len;
    u8 icmp_range_len;
// Set to prevent creating new binding and corresponding CTs
#define EXTERNAL_DELETING_FLAG (1 << 0)
#define EXTERNAL_NO_SNAT_FLAG (1 << 1)
    u8 flags;
};

struct dest_config {
#define DEST_HAIRPIN_FLAG (1 << 0)
#define DEST_NO_SNAT_FLAG (1 << 1)
    u8 flags;
};

#define BINDING_ORIG_DIR_FLAG (1 << 0)
#define FRAG_TRACK_EGRESS_FLAG (1 << 0)
#define ADDR_IPV4_FLAG (1 << 1)
#define ADDR_IPV6_FLAG (1 << 2)

// NOTE: all map key structs have to explicitly padded and the padding fields
// need to be zeroed

struct map_frag_track_key {
    u32 ifindex;
    u8 flags;
    u8 l4proto;
    u16 _pad;
    u32 id;
    union u_inet_addr saddr;
    union u_inet_addr daddr;
};

struct map_frag_track_value {
    __be16 sport;
    __be16 dport;
    u32 _pad;
    struct bpf_timer timer;
};

// If BINDING_ORIG_DIR_FLAG is set, "from" is internal source address and "to"
// is mapped external source address, otherwise the relations are reversed.
// We duplicate binding entries for both direction for looking up from both
// ingress and egress.
struct map_binding_key {
    u32 ifindex;
    u8 flags;
    u8 l4proto;
    // ICMP ID in the case of ICMP
    __be16 from_port;
    union u_inet_addr from_addr;
};

struct map_binding_value {
    union u_inet_addr to_addr;
    __be16 to_port;
    u8 flags;
    u8 is_static;
    // We only do binding ref counting on inbound direction, i.e. no
    // BINDING_ORIG_DIR_FLAG on binding key
    u32 use;
    u32 ref;
};

struct map_ct_key {
    u32 ifindex;
    u8 flags;
    u8 l4proto;
    u16 _pad;
    struct inet_tuple external;
};

enum ct_state {
    CT_IN_ONLY,
    CT_ESTABLISHED,
};

struct map_ct_value {
    struct inet_tuple origin;
    u8 flags;
    u8 _pad1;
    u16 state;
    u32 last_seen;
    u32 _pad2;
    struct bpf_timer timer;
};

#define COPY_ADDR6(t, s) (__builtin_memcpy((t), (s), sizeof(t)))
#define ADDR6_EQ(t, s) (0 == __builtin_memcmp((t), (s), sizeof(t)))

static __always_inline void inet_addr_set_ip(union u_inet_addr *addr,
                                             __be32 ip) {
    addr->ip = ip;
#ifdef FEAT_IPV6
    addr->all[1] = 0;
    addr->all[2] = 0;
    addr->all[3] = 0;
#endif
}

#ifdef FEAT_IPV6
static __always_inline void inet_addr_set_ip6(union u_inet_addr *addr,
                                              __be32 ip6[4]) {
    COPY_ADDR6(addr->ip6, ip6);
}
#endif

static __always_inline void inet_tuple_copy(struct inet_tuple *t1,
                                            const struct inet_tuple *t2) {

    COPY_ADDR6(t1->saddr.all, t2->saddr.all);
    COPY_ADDR6(t1->daddr.all, t2->daddr.all);
    t1->sport = t2->sport;
    t1->dport = t2->dport;
}

static __always_inline void inet_tuple_rev_copy(struct inet_tuple *t1,
                                                const struct inet_tuple *t2) {

    COPY_ADDR6(t1->saddr.all, t2->daddr.all);
    COPY_ADDR6(t1->daddr.all, t2->saddr.all);
    t1->sport = t2->dport;
    t1->dport = t2->sport;
}

static __always_inline void
binding_value_to_key(u32 ifindex, u8 flags, u8 l4proto,
                     const struct map_binding_value *val,
                     struct map_binding_key *key_rev) {
    key_rev->ifindex = ifindex;
    key_rev->flags = (val->flags & (~BINDING_ORIG_DIR_FLAG)) | flags;
    key_rev->l4proto = l4proto;
    key_rev->from_port = val->to_port;
    COPY_ADDR6(key_rev->from_addr.all, val->to_addr.all);
}

static __always_inline void
get_rev_dir_binding_key(const struct map_binding_key *key,
                        const struct map_binding_value *val,
                        struct map_binding_key *key_rev) {
    binding_value_to_key(
        key->ifindex,
        ((key->flags & BINDING_ORIG_DIR_FLAG) ^ BINDING_ORIG_DIR_FLAG),
        key->l4proto, val, key_rev);
}

static __always_inline u8 select_port_range(struct external_config *ext_config,
                                            u8 l4proto,
                                            struct port_range **proto_range) {
    switch (l4proto) {
    case IPPROTO_TCP:
        *proto_range = ext_config->tcp_range;
        return ext_config->tcp_range_len;
    case IPPROTO_UDP:
        *proto_range = ext_config->udp_range;
        return ext_config->udp_range_len;
    case IPPROTO_ICMP:
    case NEXTHDR_ICMP:
        *proto_range = ext_config->icmp_range;
        return ext_config->icmp_range_len;
    }
    return 0;
}

static __always_inline int
find_port_range_idx(u16 port, u8 range_len,
                    const struct port_range range_list[MAX_PORT_RANGES]) {
#pragma unroll
    for (int i = 0; i < MAX_PORT_RANGES; i++) {
        if (i >= range_len) {
            break;
        }
        const struct port_range *range = &range_list[i];

        if (port >= range->begin_port && port <= range->end_port) {
            return i;
        }
    }
    return -1;
}

static __always_inline int get_l3_to_addr_off(bool is_ipv4, bool is_source) {
    return is_source ? (is_ipv4 ? offsetof(struct iphdr, saddr)
                                : offsetof(struct ipv6hdr, saddr))
                     : (is_ipv4 ? offsetof(struct iphdr, daddr)
                                : offsetof(struct ipv6hdr, daddr));
}

static __always_inline int bpf_write_inet_addr(struct __sk_buff *skb,
                                               bool is_ipv4, int addr_off,
                                               union u_inet_addr *to_addr) {
    return bpf_skb_store_bytes(
        skb, addr_off, is_ipv4 ? &to_addr->ip : to_addr->all,
        is_ipv4 ? sizeof(to_addr->ip) : sizeof(to_addr->all), 0);
}

static __always_inline int bpf_write_port(struct __sk_buff *skb, int port_off,
                                          __be16 to_port) {
    return bpf_skb_store_bytes(skb, port_off, &to_port, sizeof(to_port), 0);
}

// Avoid modifying context register while accessing data, data_end fields,
// copied from cilium, see
// https://github.com/cilium/cilium/commit/847014aa62f94e5a53178670cad1eacea455b227
#define DEFINE_FUNC_CTX_POINTER(FIELD)                                         \
    static __always_inline void *ctx_##FIELD(const struct __sk_buff *ctx) {    \
        u8 *ptr;                                                               \
                                                                               \
        /* LLVM may generate u32 assignments of                                \
         * ctx->{data,data_end,data_meta}. With this inline asm, LLVM loses    \
         * track of the fact this field is on 32 bits.                         \
         */                                                                    \
        asm volatile("%0 = *(u32 *)(%1 + %2)"                                  \
                     : "=r"(ptr)                                               \
                     : "r"(ctx), "i"(offsetof(struct __sk_buff, FIELD)));      \
        return ptr;                                                            \
    }
/* This defines ctx_data(). */
DEFINE_FUNC_CTX_POINTER(data)
/* This defines ctx_data_end(). */
DEFINE_FUNC_CTX_POINTER(data_end)
/* This defines ctx_data_meta(). */
DEFINE_FUNC_CTX_POINTER(data_meta)
#undef DEFINE_FUNC_CTX_POINTER

// `len` needs to be a constant number
static __always_inline int _validate_pull(struct __sk_buff *skb, void **hdr_,
                                          u32 off, u32 len) {
    u8 *data = (u8 *)ctx_data(skb);
    u8 *data_end = (u8 *)ctx_data_end(skb);
    u8 *hdr = data + off;

    if (hdr + len > data_end) {
        if (bpf_skb_pull_data(skb, off + len)) {
            return 1;
        }
        data = (u8 *)ctx_data(skb);
        data_end = (u8 *)ctx_data_end(skb);
        hdr = data + off;
        if (hdr + len > data_end) {
            return 1;
        }
    }

    *hdr_ = hdr;

    return 0;
}

#define VALIDATE_PULL(skb, hdr, off, len)                                      \
    (_validate_pull(skb, (void **)hdr, off, len))
