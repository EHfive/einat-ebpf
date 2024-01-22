// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

#include "kernel/vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_log.h"

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

#define NEXTHDR_TCP 6        /* TCP segment. */
#define NEXTHDR_UDP 17       /* UDP message. */
#define NEXTHDR_ICMP 58     /* ICMP for IPv6. */
#define NEXTHDR_NONE 59     /* No next header */
#define NEXTHDR_SCTP 132     /* SCTP message. */

#define IPV6_FRAG_OFFSET 0xFFF8
#define IPV6_FRAG_MF 0x0001

#define AF_INET 2
#define AF_INET6 10

#define CLOCK_MONOTONIC 1

// #include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define BPF_LOOP_RET_CONTINUE 0
#define BPF_LOOP_RET_BREAK 1

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

#define MAX_PORT_RANGES 16

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
#define ADDR_IPV6_FLAG (1 << 2) // not supported yet

struct map_frag_track_key {
    u32 ifindex;
    u8 flags;
    u8 l4proto;
    __be16 id;
    union u_inet_addr saddr;
    union u_inet_addr daddr;
};

struct map_frag_track_value {
    __be16 sport;
    __be16 dport;

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
    u8 _pad[2];
    struct inet_tuple external;
};

enum ct_state {
    CT_IN_ONLY,
    CT_ESTABLISHED,
};

struct map_ct_value {
    struct inet_tuple origin;
    u8 flags;
    u16 state;
    u32 last_seen;
    struct bpf_timer timer;
};

#define COPY_ADDR6(t, s) (__builtin_memcpy((t), (s), sizeof(t)))
#define ADDR6_EQ(t, s) (0 == __builtin_memcmp((t), (s), sizeof(t)))

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
get_rev_dir_binding_key(struct map_binding_key *key_rev,
                        const struct map_binding_key *key,
                        const struct map_binding_value *val) {
    key_rev->ifindex = key->ifindex;
    key_rev->flags =
        (val->flags & (~BINDING_ORIG_DIR_FLAG)) |
        ((key->flags & BINDING_ORIG_DIR_FLAG) ^ BINDING_ORIG_DIR_FLAG);
    key_rev->l4proto = key->l4proto;
    key_rev->from_port = val->to_port;
    COPY_ADDR6(key_rev->from_addr.all, val->to_addr.all);
}

static __always_inline int
find_port_range_idx(u16 port, u32 range_len,
                    const struct port_range range_list[MAX_PORT_RANGES]) {
#pragma unroll
    for (int i = 0; i < MAX_PORT_RANGES; i++) {
        if (i >= range_len) {
            break;
        }
        const struct port_range *range = &range_list[i];

        if (range->end_port == 0) {
            break;
        }
        if (port >= range->begin_port && port <= range->end_port) {
            return i;
        }
    }
    return -1;
}
