// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#include "full_cone_nat.h"

#define DEFAULT_FRAG_TRACK_MAX_ENTRIES 8192
#define DEFAULT_BINDING_MAX_ENTRIES (65536 * 2)
#define DEFAULT_CONNTRACK_MAX_ENTRIES (65536 * 2)

// Lookup external source address from FIB instead of using
// g_ipv4_external_addr, requires Linux kernel>=6.7
const volatile u8 ENABLE_FIB_LOOKUP_SRC = 0;

u32 g_ipv4_external_addr SEC(".data") = 0;
u8 g_log_level SEC(".data") = BPF_LOG_LEVEL_DEBUG;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL g_log_level

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct external_config);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ipv4_external_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct dest_config);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ipv4_dest_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct map_frag_track_key);
    __type(value, struct map_frag_track_value);
    __uint(max_entries, DEFAULT_FRAG_TRACK_MAX_ENTRIES);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_frag_track SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct map_binding_key);
    __type(value, struct map_binding_value);
    __uint(max_entries, DEFAULT_BINDING_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_binding SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct map_ct_key);
    __type(value, struct map_ct_value);
    __uint(max_entries, DEFAULT_CONNTRACK_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_ct SEC(".maps");

struct packet_info {
    u8 is_ipv4;
    u8 l4proto;
    u8 is_fragment;
    __be16 id;
    struct inet_tuple tuple;
    struct ethhdr *eth;
    union {
        struct iphdr *iph;
        struct ipv6hdr *ip6h;
    };
    union {
        struct tcphdr *tcph;
        struct udphdr *udph;
        struct icmphdr *icmph;
        struct icmp6hdr *icmp6h;
    };
};

static __always_inline int parse_packet(const struct __sk_buff *skb,
                                        struct packet_info *pkt) {
    void *data_end = (void *)(long)skb->data_end;
    pkt->eth = (struct ethhdr *)(void *)(long)skb->data;

    void *trans_data;
    __be16 src_port = 0;
    __be16 dst_port = 0;

    if ((void *)(pkt->eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (pkt->eth->h_proto == bpf_htons(ETH_P_IP)) {
        pkt->iph = (struct iphdr *)((void *)pkt->eth + sizeof(*pkt->eth));
        if ((void *)(pkt->iph + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        pkt->tuple.saddr.ip = pkt->iph->saddr;
        pkt->tuple.daddr.ip = pkt->iph->daddr;
        pkt->is_ipv4 = true;
        pkt->l4proto = pkt->iph->protocol;
        trans_data = (void *)pkt->iph + (pkt->iph->ihl * 4);
    } else if (pkt->eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        pkt->ip6h = (struct ipv6hdr *)((void *)pkt->eth + sizeof(*pkt->eth));
        if ((void *)(pkt->ip6h + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        COPY_ADDR6(pkt->tuple.saddr.ip6, pkt->ip6h->saddr.in6_u.u6_addr32);
        COPY_ADDR6(pkt->tuple.daddr.ip6, pkt->ip6h->daddr.in6_u.u6_addr32);
        pkt->is_ipv4 = false;
        // FIXME: iterate nexthdr to find out fragmentation header and/or L4
        // protocol header
        pkt->l4proto = pkt->ip6h->nexthdr;
        trans_data = pkt->ip6h + 1;
    } else {
        return TC_ACT_UNSPEC;
    }

    if (pkt->l4proto == IPPROTO_TCP) {
        pkt->tcph = trans_data;
        if ((void *)(pkt->tcph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        pkt->tuple.sport = pkt->tcph->source;
        pkt->tuple.dport = pkt->tcph->dest;
    } else if (pkt->l4proto == IPPROTO_UDP) {
        pkt->udph = trans_data;
        if ((void *)(pkt->udph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        pkt->tuple.sport = pkt->udph->source;
        pkt->tuple.dport = pkt->udph->dest;
    } else if (pkt->is_ipv4 && pkt->l4proto == IPPROTO_ICMP) {
        pkt->icmph = trans_data;
        if ((void *)(pkt->icmph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        // TODO: parse ICMP content
    } else if (!pkt->is_ipv4 && pkt->l4proto == NEXTHDR_ICMP) {
        pkt->icmp6h = trans_data;
        if ((void *)(pkt->icmp6h + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        // TODO: parse ICMPv6 content
    } else {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
}

static __always_inline int ipv4_update_csum(struct __sk_buff *skb, u32 l3_off,
                                            u32 l4_off, __be32 from_addr,
                                            __be16 from_port, __be32 to_addr,
                                            __be16 to_port) {
    int ret;
    u32 ip_check_off = l3_off + offsetof(struct iphdr, check);
    u32 udp_check_off = l4_off + offsetof(struct udphdr, check);

    ret = bpf_l4_csum_replace(skb, udp_check_off, from_port, to_port,
                              2 | BPF_F_MARK_MANGLED_0);
    if (ret)
        return ret;
    ret = bpf_l4_csum_replace(skb, udp_check_off, from_addr, to_addr,
                              4 | BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR);
    if (ret)
        return ret;
    ret = bpf_l3_csum_replace(skb, ip_check_off, from_addr, to_addr, 4);
    if (ret)
        return ret;

    return 0;
}

static __always_inline struct map_binding_value *
insert_new_binding(const struct map_binding_key *key,
                   const struct map_binding_value *val,
                   struct map_binding_value **lk_val_rev) {
#define BPF_LOG_TOPIC "insert_new_binding"
    int ret;
    struct map_binding_key key_rev;
    get_rev_dir_binding_key(&key_rev, key, val);

    struct map_binding_value val_rev = {
        .flags = key->flags & (~BINDING_ORIG_DIR_FLAG),
        .to_port = key->from_port,
        .to_addr = key->from_addr,
        .use = 0,
    };
    ret = bpf_map_update_elem(&map_binding, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert binding entry, err:%d", ret);
        return NULL;
    }
    ret = bpf_map_update_elem(&map_binding, &key_rev, &val_rev, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert reverse binding entry, err:%d", ret);
        bpf_map_delete_elem(&map_binding, key);
        return NULL;
    }

    if (lk_val_rev) {
        *lk_val_rev = bpf_map_lookup_elem(&map_binding, &key_rev);
        if (!*lk_val_rev) {
            return NULL;
        }
    }

    return bpf_map_lookup_elem(&map_binding, key);
#undef BPF_LOG_TOPIC
}

static __always_inline void delete_ct(struct map_ct_key *key) {
#define BPF_LOG_TOPIC "delete_ct"
    struct map_binding_key b_key = {
        .ifindex = key->ifindex,
        .flags = key->flags,
        .l4proto = key->l4proto,
        .from_addr = key->external.saddr,
        .from_port = key->external.sport,
    };
    struct map_ct_value *ct_value = bpf_map_lookup_elem(&map_ct, key);
    if (!ct_value) {
        return;
    }

    struct map_binding_value *b_value =
        bpf_map_lookup_elem(&map_binding, &b_key);
    if (!b_value) {
        goto delete_ct;
    }
    if (ct_value->state == CT_IN_ONLY) {
        if (__sync_sub_and_fetch(&b_value->ref, 1) != 0) {
            goto delete_ct;
        }
    } else if (__sync_sub_and_fetch(&b_value->use, 1),
               __sync_sub_and_fetch(&b_value->ref, 1) != 0) {
        goto delete_ct;
    }

    struct map_binding_key b_key_orig;
    get_rev_dir_binding_key(&b_key_orig, &b_key, b_value);

    bpf_map_delete_elem(&map_binding, &b_key_orig);
    bpf_map_delete_elem(&map_binding, &b_key);

    bpf_log_debug("no ref, delete binding");

delete_ct:
    bpf_map_delete_elem(&map_ct, key);
#undef BPF_LOG_TOPIC
}

static int ct_timer_cb(void *_map_ct, struct map_ct_key *key,
                       struct bpf_timer *timer) {
#define BPF_LOG_TOPIC "ct_timer_cb"
    bpf_log_debug("timeout: delete CT %pI4 -> %pI4", &key->external.saddr.ip,
                  &key->external.daddr.ip);

    delete_ct(key);
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct map_ct_value *
insert_new_ct(const struct map_ct_key *key, const struct map_ct_value *val) {
#define BPF_LOG_TOPIC "insert_new_ct"
    int ret = bpf_map_update_elem(&map_ct, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert conntrack entry, err:%d", ret);
        return NULL;
    }
    struct map_ct_value *value = bpf_map_lookup_elem(&map_ct, key);
    if (!value)
        return NULL;

    ret = bpf_timer_init(&value->timer, &map_ct, CLOCK_MONOTONIC);
    if (ret) {
        bpf_log_error("failed to init timer, err:%d", ret);
        goto delete_ct;
    }
    ret = bpf_timer_set_callback(&value->timer, ct_timer_cb);
    if (ret) {
        bpf_log_error("failed to set timer callback, err:%d", ret);
        goto delete_ct;
    }
    ret = bpf_timer_start(&value->timer, 30E9, 0);
    if (ret) {
        bpf_log_error("failed to start timer, err:%d", ret);
        goto delete_ct;
    }

    return value;
delete_ct:
    bpf_map_delete_elem(&map_ct, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int ingress_rev_snat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "ingress<=="
    int ret;
    struct packet_info pkt = {};

    ret = parse_packet(skb, &pkt);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    if (pkt.l4proto != IPPROTO_UDP || !pkt.is_ipv4) {
        return TC_ACT_UNSPEC;
    }

    struct ipv4_lpm_key dest_key = {.prefixlen = 32, .ip = pkt.tuple.saddr.ip};
    struct dest_config *dest_config =
        bpf_map_lookup_elem(&map_ipv4_dest_config, &dest_key);
    if (dest_config && (dest_config->flags & DEST_NO_SNAT_FLAG)) {
        return TC_ACT_UNSPEC;
    }

    struct ipv4_lpm_key ext_key = {.prefixlen = 32, .ip = pkt.tuple.daddr.ip};
    struct external_config *ext_config =
        bpf_map_lookup_elem(&map_ipv4_external_config, &ext_key);
    if (!ext_config) {
        // XXX: drop or passthrough?
        return TC_ACT_SHOT;
    }
    if (ext_config->flags & EXTERNAL_NO_SNAT_FLAG) {
        return TC_ACT_UNSPEC;
    }
    if (ext_config->flags & EXTERNAL_DELETING_FLAG) {
        return TC_ACT_SHOT;
    }

    bool in_range = false;
    u32 ext_port = bpf_ntohs(pkt.tuple.dport);

#pragma unroll
    for (int i = 0; i < MAX_PORT_RANGES; i++) {
        struct port_range *range = &ext_config->udp_range[i];
        if (range->end_port == 0) {
            break;
        }
        if (ext_port >= range->begin_port && ext_port <= range->end_port) {
            in_range = true;
            break;
        }
    }
    if (!in_range) {
        bpf_log_trace("external port %d not in mapping range, passthrough",
                      ext_port);
        return TC_ACT_UNSPEC;
    }

    // TODO: do static binding instead

    bpf_log_debug("src:%pI4 dst:%pI4", &pkt.tuple.saddr.ip,
                  &pkt.tuple.daddr.ip);

    struct map_ct_key ct_key = {
        .ifindex = skb->ifindex,
        .flags = ADDR_IPV4_FLAG,
        .l4proto = pkt.l4proto,
    };
    inet_tuple_rev_copy(&ct_key.external, &pkt.tuple);

    struct map_ct_value *ct_value = bpf_map_lookup_elem(&map_ct, &ct_key);
    if (!ct_value) {
        struct map_binding_key b_key = {
            .ifindex = skb->ifindex,
            .flags = ADDR_IPV4_FLAG,
            .l4proto = pkt.l4proto,
            .from_port = pkt.tuple.dport,
            .from_addr = pkt.tuple.daddr,
        };

        struct map_binding_value *b_value =
            bpf_map_lookup_elem(&map_binding, &b_key);
        if (!b_value || __sync_fetch_and_add(&b_value->use, 0) == 0) {
            // TODO: add to pending conntrack table if no mapping
            // TODO: delay and send back ICMP port unreachable
            bpf_log_debug("mapping not active");
            return TC_ACT_SHOT;
        }

        struct map_ct_value ct_value_new = {
            .flags = ADDR_IPV4_FLAG,
            .origin = ct_key.external,
            .state = CT_IN_ONLY,
        };
        COPY_ADDR6(ct_value_new.origin.saddr.all, b_value->to_addr.all);
        ct_value_new.origin.sport = b_value->to_port;

        ct_value = insert_new_ct(&ct_key, &ct_value_new);
        if (!ct_value) {
            return TC_ACT_SHOT;
        }
        __sync_fetch_and_add(&b_value->ref, 1);

        bpf_log_debug("insert new CT");
    } else if (ct_value->state == CT_IN_ONLY) {
        struct map_binding_key b_key = {
            .ifindex = skb->ifindex,
            .flags = ADDR_IPV4_FLAG,
            .l4proto = pkt.l4proto,
            .from_port = pkt.tuple.dport,
            .from_addr = pkt.tuple.daddr,
        };

        struct map_binding_value *b_value =
            bpf_map_lookup_elem(&map_binding, &b_key);
        if (!b_value) {
            return TC_ACT_SHOT;
        }

        if (__sync_fetch_and_add(&b_value->use, 0) != 0) {
            bpf_log_error("refresh CT");
            bpf_timer_start(&ct_value->timer, 30E9, 0);
        }
    }

    // modify dest

    u32 l3_off = (void *)pkt.iph - (void *)pkt.eth;
    u32 l4_off = (void *)pkt.udph - (void *)pkt.eth;

    pkt.iph->daddr = ct_value->origin.saddr.ip;
    pkt.udph->dest = ct_value->origin.sport;

    ret = ipv4_update_csum(skb, l3_off, l4_off, ct_key.external.saddr.ip,
                           ct_key.external.sport, ct_value->origin.saddr.ip,
                           ct_value->origin.sport);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

int __always_inline lookup_src(struct __sk_buff *skb, struct packet_info *pkt) {
#define BPF_LOG_TOPIC "lookup_src"
    struct bpf_fib_lookup params = {
        .family = AF_INET,
        .ifindex = skb->ifindex,
    };

    params.ifindex = skb->ifindex;
    params.ipv4_src = pkt->tuple.saddr.ip;
    params.ipv4_dst = pkt->tuple.daddr.ip;
    int ret = bpf_fib_lookup(skb, &params, sizeof(params),
                             BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
    bpf_log_debug("out, ret:%d, src:%pI4 orig_dst:%pI4 dst:%pI4 if:%d", ret,
                  &params.ipv4_src, &pkt->tuple.daddr.ip, &params.ipv4_dst,
                  params.ifindex);

    return 0;
#undef BPF_LOG_TOPIC
}

struct find_port_ctx {
    struct map_binding_key key;
    u32 orig_port;
    struct port_range range;
    int curr_remaining;
    u32 curr_port;
    bool found;
};

static int find_port_cb(u32 index, struct find_port_ctx *ctx) {
#define BPF_LOG_TOPIC "find_binding_port"
    ctx->key.from_port = bpf_htons(ctx->curr_port);
    struct map_binding_value *value =
        bpf_map_lookup_elem(&map_binding, &ctx->key);
    if (!value) {
        bpf_log_debug("found free binding %d -> %d", ctx->orig_port,
                      ctx->curr_port);
        ctx->found = true;
        return BPF_LOOP_RET_BREAK;
    }

    bpf_log_trace("binding %d -> %d used", ctx->orig_port, ctx->curr_port);

    if (ctx->curr_port != ctx->range.end_port) {
        ctx->curr_port++;
    } else {
        ctx->curr_port = ctx->range.begin_port;
    }
    if (--ctx->curr_remaining == 0) {
        return BPF_LOOP_RET_BREAK;
    }

    return BPF_LOOP_RET_CONTINUE;
#undef BPF_LOG_TOPIC
}

static int __always_inline
fill_unique_binding_port(const struct map_binding_key *key_orig,
                         struct map_binding_value *val_orig) {
#define BPF_LOG_TOPIC "find_binding_port"
    struct ipv4_lpm_key ext_key = {.prefixlen = 32, .ip = val_orig->to_addr.ip};
    struct external_config *ext_config =
        bpf_map_lookup_elem(&map_ipv4_external_config, &ext_key);
    if (!ext_config) {
        return TC_ACT_SHOT;
    }
    if (ext_config->flags & EXTERNAL_NO_SNAT_FLAG) {
        return TC_ACT_UNSPEC;
    }
    if (ext_config->flags & EXTERNAL_DELETING_FLAG) {
        return TC_ACT_SHOT;
    }

    u32 range_len = ext_config->udp_range_len;
    if (range_len == 0) {
        return TC_ACT_SHOT;
    }

    struct find_port_ctx ctx;

    get_rev_dir_binding_key(&ctx.key, key_orig, val_orig);
    ctx.orig_port = bpf_ntohs(key_orig->from_port);
    ctx.curr_port = bpf_ntohs(ctx.key.from_port);
    ctx.found = false;

    int start_range_idx = -1;
#pragma unroll
    for (int i = 0; i < MAX_PORT_RANGES; i++) {
        if (i >= range_len) {
            break;
        }
        struct port_range *range = &ext_config->udp_range[i];
        if (range->end_port == 0) {
            range_len = i;
            break;
        }

        if (ctx.curr_port >= range->begin_port &&
            ctx.curr_port <= range->end_port) {
            start_range_idx = i;
            break;
        }
    }
    if (start_range_idx < 0) {
        start_range_idx = bpf_get_prandom_u32() % range_len;
    }

#pragma unroll
    for (int i = 0; i < MAX_PORT_RANGES; i++) {
        if (i >= range_len) {
            break;
        }
        u32 idx = (start_range_idx + i) % range_len % MAX_PORT_RANGES;

        ctx.range = ext_config->udp_range[idx];
        ctx.curr_remaining = ctx.range.end_port - ctx.range.begin_port + 1;
        if (ctx.curr_remaining <= 0) {
            bpf_log_error("invalid port range [%d, %d]", ctx.range.begin_port,
                          ctx.range.end_port);
            continue;
        }
        if (ctx.curr_port < ctx.range.begin_port ||
            ctx.curr_port > ctx.range.end_port) {
            ctx.curr_port = (bpf_get_prandom_u32() % ctx.curr_remaining) +
                            ctx.range.begin_port;
        }

        bpf_loop(65535, find_port_cb, &ctx, 0);
        if (ctx.found) {
            val_orig->to_port = ctx.key.from_port;
            return TC_ACT_OK;
        }
    }

    bpf_log_warn("out of binding port");
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int egress_snat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "egress ==>"
    int ret;
    struct packet_info pkt = {};

    ret = parse_packet(skb, &pkt);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }
    if (pkt.l4proto != IPPROTO_UDP || !pkt.is_ipv4) {
        return TC_ACT_UNSPEC;
    }

    struct ipv4_lpm_key dest_key = {.prefixlen = 32, .ip = pkt.tuple.daddr.ip};
    struct dest_config *dest_config =
        bpf_map_lookup_elem(&map_ipv4_dest_config, &dest_key);
    if (dest_config && (dest_config->flags & DEST_NO_SNAT_FLAG)) {
        goto check_hairpin;
    }

    struct ipv4_lpm_key ext_key = {.prefixlen = 32, .ip = pkt.tuple.saddr.ip};
    struct external_config *ext_config =
        bpf_map_lookup_elem(&map_ipv4_external_config, &ext_key);
    if (ext_config) {
        if (ext_config->flags & EXTERNAL_NO_SNAT_FLAG) {
            goto check_hairpin;
        }
        if (ext_config->flags & EXTERNAL_DELETING_FLAG) {
            return TC_ACT_SHOT;
        }

        bool in_range = false;
        u32 ext_port = bpf_ntohs(pkt.tuple.sport);

#pragma unroll
        for (int i = 0; i < MAX_PORT_RANGES; i++) {
            if (i >= ext_config->udp_range_len) {
                break;
            }
            struct port_range *range = &ext_config->udp_range[i];
            if (range->end_port == 0) {
                break;
            }
            if (ext_port >= range->begin_port && ext_port <= range->end_port) {
                in_range = true;
                break;
            }
        }
        if (!in_range) {
            bpf_log_trace("external port %d not in mapping range, passthrough",
                          ext_port);
            return TC_ACT_UNSPEC;
        }

        if (false) {
            // Disallow TCP/UDP SNAT for external IP, i.e. disallow binding
            // <external IP>:<internal port> -> <external IP>:<external port>.
            //
            // ICMP ID remapping for external IP is needed as Linux allows
            // setting arbitrary ICMP ID which would cause collision with ICMP
            // ID binding of other internal source.
            if (pkt.l4proto == IPPROTO_UDP || pkt.l4proto != IPPROTO_TCP) {
                return TC_ACT_SHOT;
            }
        }
    }

    struct map_binding_key b_key_rev;
    struct map_binding_key b_key = {
        .ifindex = skb->ifindex,
        .flags = BINDING_ORIG_DIR_FLAG | ADDR_IPV4_FLAG,
        .l4proto = pkt.l4proto,
        .from_port = pkt.tuple.sport,
        .from_addr = pkt.tuple.saddr,
    };

    struct map_binding_value *b_value_rev = NULL;
    struct map_binding_value *b_value =
        bpf_map_lookup_elem(&map_binding, &b_key);
    if (!b_value) {
        struct map_binding_value b_value_new = {
            .flags = ADDR_IPV4_FLAG,
            .to_port = b_key.from_port,
            .use = 0,
        };
        b_value_new.to_addr.ip = g_ipv4_external_addr;

        ret = fill_unique_binding_port(&b_key, &b_value_new);
        if (ret == TC_ACT_UNSPEC) {
            goto check_hairpin;
        } else if (ret != TC_ACT_OK) {
            // XXX: no free port, send back ICMP port unreachable?
            return TC_ACT_SHOT;
        }

        b_value = insert_new_binding(&b_key, &b_value_new, &b_value_rev);
        if (!b_value || !b_value_rev) {
            return TC_ACT_SHOT;
        }
    }

    struct map_ct_key ct_key = {
        .ifindex = b_key.ifindex,
        .flags = ADDR_IPV4_FLAG,
        .l4proto = b_key.l4proto,
        .external = pkt.tuple,
    };

    COPY_ADDR6(ct_key.external.saddr.all, b_value->to_addr.all);
    ct_key.external.sport = b_value->to_port;

    struct map_ct_value *ct_value = bpf_map_lookup_elem(&map_ct, &ct_key);
    if (!ct_value) {
        if (!b_value_rev) {
            get_rev_dir_binding_key(&b_key_rev, &b_key, b_value);

            b_value_rev = bpf_map_lookup_elem(&map_binding, &b_key_rev);
            if (!b_value_rev) {
                // racing, no reverse binding
                return TC_ACT_SHOT;
            }
        }

        struct map_ct_value ct_value_new = {
            .flags = ADDR_IPV4_FLAG,
            .origin = pkt.tuple,
            .state = CT_ESTABLISHED,
        };
        ct_value = insert_new_ct(&ct_key, &ct_value_new);
        if (!ct_value) {
            return TC_ACT_SHOT;
        }
        __sync_fetch_and_add(&b_value_rev->ref, 1);
        __sync_fetch_and_add(&b_value_rev->use, 1);

        bpf_log_debug("insert new CT");
    } else if (ct_value->state == CT_IN_ONLY) {
        get_rev_dir_binding_key(&b_key_rev, &b_key, b_value);
        b_value_rev = bpf_map_lookup_elem(&map_binding, &b_key_rev);
        if (!b_value_rev) {
            // racing, no reverse binding
            return TC_ACT_SHOT;
        }

        // XXX: use lock?
        ct_value->state = CT_ESTABLISHED;
        __sync_fetch_and_add(&b_value_rev->use, 1);

        bpf_log_debug("found existing inbound initialized CT");
    }

    u32 l3_off = (void *)pkt.iph - (void *)pkt.eth;
    u32 l4_off = (void *)pkt.udph - (void *)pkt.eth;

    pkt.iph->saddr = ct_key.external.saddr.ip;
    pkt.udph->source = ct_key.external.sport;

    ret = ipv4_update_csum(skb, l3_off, l4_off, ct_value->origin.saddr.ip,
                           ct_value->origin.sport, ct_key.external.saddr.ip,
                           ct_key.external.sport);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    bpf_timer_start(&ct_value->timer, 300E9, 0);

check_hairpin:
    if (dest_config->flags & DEST_HAIRPIN_FLAG) {
        // TODO: redirect to ingress
    }
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

#define NF_DROP 0
#define NF_ACCEPT 1

char _license[] SEC("license") = "GPL";
