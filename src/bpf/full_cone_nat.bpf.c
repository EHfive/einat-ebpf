// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#include "full_cone_nat.h"

#define DEFAULT_FRAG_TRACK_MAX_ENTRIES 8192
#define DEFAULT_BINDING_MAX_ENTRIES (65536 * 2)
#define DEFAULT_CONNTRACK_MAX_ENTRIES (65536 * 2)

// Lookup external source address from FIB instead of using
// g_ipv4_external_addr, requires Linux kernel>=6.7
const volatile u8 ENABLE_FIB_LOOKUP_SRC = 0;

// at least FRAGMENT_MIN=2s,
// https://datatracker.ietf.org/doc/html/rfc6146#section-4
const volatile u64 TIMEOUT_FRAGMENT = 2E9;

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

#ifdef FEAT_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct external_config);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ipv6_external_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct dest_config);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ipv6_dest_config SEC(".maps");
#endif

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
#ifdef FEAT_IPV6
    bool is_ipv4;
#endif
    // `nexthdr` and `tuple` fields reflect embedded ICMP error IP packet in
    // case of ICMP error message, otherwise reflect TCP, UDP, or ICMP query
    // message.
    u8 nexthdr;
#define FRAG_NONE 0
#define FRAG_MORE 1
#define FRAG_LAST 2
    u8 frag_type;
    u16 frag_off;
    u32 frag_id;
    struct inet_tuple tuple;
    int l4_off;
    // ICMP error message
    int err_l4_off;
};

#ifdef FEAT_IPV6
#define IS_IPV4(pkt) ((pkt)->is_ipv4)
#define FLAGS_IS_IPV4(flags) ((flags)&ADDR_IPV4_FLAG)
#else
#define IS_IPV4(pkt) (true)
#define FLAGS_IS_IPV4(flags) (true)
#endif

static __always_inline bool is_icmpx(u8 nexthdr) {
#ifdef FEAT_IPV6
    return nexthdr == IPPROTO_ICMP || nexthdr == NEXTHDR_ICMP;
#else
    return nexthdr == IPPROTO_ICMP;
#endif
}

static __always_inline int icmpx_err_l3_offset(int l4_off) {
    return l4_off + sizeof(struct icmphdr);
}

static __always_inline bool is_icmpx_error_pkt(const struct packet_info *pkt) {
    return pkt->l4_off >= 0 && pkt->err_l4_off >= 0;
}

static __always_inline int parse_ipv4_packet_light(const struct iphdr *iph,
                                                   struct inet_tuple *tuple,
                                                   u8 *nexthdr) {
#define BPF_LOG_TOPIC "parse_ipv4_packet_light"
    if (iph->version != 4) {
        return -1;
    }
    inet_addr_set_ip(&tuple->saddr, iph->saddr);
    inet_addr_set_ip(&tuple->daddr, iph->daddr);
    *nexthdr = iph->protocol;
    if (iph->frag_off & bpf_htons(IP_OFFSET)) {
        return -1;
    }
    return (iph->ihl * 4);
#undef BPF_LOG_TOPIC
}

static __always_inline int parse_ipv4_packet(struct packet_info *pkt,
                                             const struct iphdr *iph) {
#define BPF_LOG_TOPIC "parse_ipv4_packet"
    if (iph->version != 4) {
        return -1;
    }
    inet_addr_set_ip(&pkt->tuple.saddr, iph->saddr);
    inet_addr_set_ip(&pkt->tuple.daddr, iph->daddr);
#ifdef FEAT_IPV6
    pkt->is_ipv4 = true;
#endif
    pkt->frag_off = bpf_ntohs((iph->frag_off & bpf_htons(IP_OFFSET)) << 3);
    if (iph->frag_off & bpf_htons(IP_MF)) {
        pkt->frag_type = FRAG_MORE;
    } else if (pkt->frag_off) {
        pkt->frag_type = FRAG_LAST;
    } else {
        pkt->frag_type = FRAG_NONE;
    }
    pkt->frag_id = bpf_ntohs(iph->id);
    pkt->nexthdr = iph->protocol;
    return (iph->ihl * 4);
#undef BPF_LOG_TOPIC
}

#ifdef FEAT_IPV6
static __always_inline int _parse_ipv6_packet(struct __sk_buff *skb, u32 l3_off,
                                              struct inet_tuple *tuple,
                                              u8 *nexthdr,
                                              struct frag_hdr *frag_hdr) {
#define BPF_LOG_TOPIC "_parse_ipv6_packet"
    struct ipv6hdr *ip6h;
    if (VALIDATE_PULL_L3(skb, &ip6h, l3_off, sizeof(*ip6h))) {
        return -1;
    }
    if (ip6h->version != 6) {
        return -1;
    }
    inet_addr_set_ip6(&tuple->saddr, ip6h->saddr.in6_u.u6_addr32);
    inet_addr_set_ip6(&tuple->daddr, ip6h->daddr.in6_u.u6_addr32);

    u32 frag_hdr_off = 0;
    int len = sizeof(struct ipv6hdr);
    *nexthdr = ip6h->nexthdr;
#pragma unroll
    for (int i = 0; i < MAX_IPV6_EXT_NUM; i++) {
        switch (*nexthdr) {
        case NEXTHDR_FRAGMENT:
            frag_hdr_off = len;
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_AUTH:
        case NEXTHDR_DEST: {
            struct ipv6_opt_hdr opthdr;
            if (bpf_skb_load_bytes(skb, l3_off + len, &opthdr,
                                   sizeof(opthdr))) {
                return -1;
            }
            if (*nexthdr != NEXTHDR_AUTH) {
                len += (opthdr.hdrlen + 1) * 8;
            } else {
                len += (opthdr.hdrlen + 2) * 4;
            }
            *nexthdr = opthdr.nexthdr;
            break;
        }
        default:
            goto found_upper_layer;
        }
    }
    return -1;

found_upper_layer:
    if (frag_hdr_off) {
        if (bpf_skb_load_bytes(skb, l3_off + frag_hdr_off, frag_hdr,
                               sizeof(*frag_hdr))) {
            return -1;
        }
    } else {
        frag_hdr->frag_off = 0;
    }
    return len;
#undef BPF_LOG_TOPIC
}

static __always_inline int parse_ipv6_packet_light(struct __sk_buff *skb,
                                                   u32 l3_off,
                                                   struct inet_tuple *tuple,
                                                   u8 *nexthdr) {
#define BPF_LOG_TOPIC "parse_ipv6_packet_light"

    struct frag_hdr frag_hdr;
    int len = _parse_ipv6_packet(skb, l3_off, tuple, nexthdr, &frag_hdr);
    if (len < 0) {
        return len;
    }

    if (frag_hdr.frag_off & bpf_htons(IPV6_FRAG_OFFSET)) {
        return -1;
    }
    return len;
#undef BPF_LOG_TOPIC
}

static __always_inline int
parse_ipv6_packet(struct __sk_buff *skb, struct packet_info *pkt, u32 l3_off) {
#define BPF_LOG_TOPIC "parse_ipv6_packet"
    pkt->is_ipv4 = false;

    struct frag_hdr frag_hdr;
    int len =
        _parse_ipv6_packet(skb, l3_off, &pkt->tuple, &pkt->nexthdr, &frag_hdr);
    if (len < 0) {
        return len;
    }

    if (frag_hdr.frag_off) {
        pkt->frag_id = bpf_ntohl(frag_hdr.identification);
        pkt->frag_off =
            bpf_ntohs(frag_hdr.frag_off & bpf_htons(IPV6_FRAG_OFFSET));

        if (frag_hdr.frag_off & bpf_htons(IPV6_FRAG_MF)) {
            pkt->frag_type = FRAG_MORE;
        } else if (pkt->frag_off) {
            pkt->frag_type = FRAG_LAST;
        } else {
            // This packet is the last fragment but also the first
            // fragment as fragmentation offset is 0, so just ignore
            // the fragmentation.
            pkt->frag_type = FRAG_NONE;
        }
    } else {
        pkt->frag_type = FRAG_NONE;
        pkt->frag_off = 0;
        pkt->frag_id = 0;
    }
    return len;
#undef BPF_LOG_TOPIC
}
#endif

enum {
    ICMP_ERROR_MSG,
    ICMP_QUERY_MSG,
    ICMP_ACT_UNSPEC,
    ICMP_ACT_SHOT,
};
static __always_inline int icmpx_msg_type(bool is_ipv4, u8 nexthdr,
                                          void *trans_data) {
    if (nexthdr == IPPROTO_ICMP) {
        if (!is_ipv4) {
            return ICMP_ACT_SHOT;
        }
        struct icmphdr *icmph = trans_data;
        switch (icmph->type) {
        case ICMP_DEST_UNREACH:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
            return ICMP_ERROR_MSG;
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
            return ICMP_QUERY_MSG;
        }
#ifdef FEAT_IPV6
    } else if (nexthdr == NEXTHDR_ICMP) {
        if (is_ipv4) {
            return TC_ACT_SHOT;
        }
        struct icmp6hdr *icmp6h = trans_data;
        switch (icmp6h->icmp6_type) {
        case ICMPV6_DEST_UNREACH:
        case ICMPV6_PKT_TOOBIG:
        case ICMPV6_TIME_EXCEED:
        case ICMPV6_PARAMPROB:
            return ICMP_ERROR_MSG;
        case ICMPV6_ECHO_REQUEST:
        case ICMPV6_ECHO_REPLY:
            return ICMP_QUERY_MSG;
        }
#endif
    }
    return ICMP_ACT_UNSPEC;
}

static __always_inline __be16 get_icmpx_query_id(struct icmphdr *icmph) {
    return icmph->un.echo.id;
}

#define ICMP_ERR_PACKET_L4_LEN 8
static __always_inline int parse_packet_light(struct __sk_buff *skb,
                                              bool is_ipv4, int l3_off,
                                              struct inet_tuple *tuple,
                                              u8 *nexthdr, int *l3_hdr_len) {
#define BPF_LOG_TOPIC "parse_packet_light"
    if (is_ipv4) {
        struct iphdr *iph;
        if (VALIDATE_PULL_L3(skb, &iph, l3_off, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        *l3_hdr_len = parse_ipv4_packet_light(iph, tuple, nexthdr);
    } else {
#ifdef FEAT_IPV6
        *l3_hdr_len = parse_ipv6_packet_light(skb, l3_off, tuple, nexthdr);
#else
        return TC_ACT_UNSPEC;
#endif
    }
    if (*l3_hdr_len < 0) {
        return TC_ACT_SHOT;
    }

    int l4_off = l3_off + *l3_hdr_len;
    if (*nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_PULL(skb, &tcph, l4_off, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        tuple->sport = tcph->source;
        tuple->dport = tcph->dest;
    } else if (*nexthdr == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_PULL(skb, &udph, l4_off, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        tuple->sport = udph->source;
        tuple->dport = udph->dest;
    } else if (is_icmpx(*nexthdr)) {
        void *icmph;
        if (VALIDATE_PULL(skb, &icmph, l4_off, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        int ret = icmpx_msg_type(is_ipv4, *nexthdr, icmph);
        switch (ret) {
        case ICMP_QUERY_MSG: {
            tuple->sport = tuple->dport = get_icmpx_query_id(icmph);
            break;
        }
        case ICMP_ERROR_MSG:
            // not parsing nested ICMP error
        case ICMP_ACT_UNSPEC:
            // ICMP message not parsed
            return TC_ACT_UNSPEC;
        default:
            bpf_log_error("icmp shot");
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int parse_packet(struct __sk_buff *skb,
                                        struct packet_info *pkt) {
#define BPF_LOG_TOPIC "parse_packet"
    void *data_end = ctx_data_end(skb);
    struct ethhdr *eth = ctx_data(skb);
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    int l3_header_len;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph;
        if (VALIDATE_PULL_L3(skb, &iph, TC_SKB_L3_OFF, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        l3_header_len = parse_ipv4_packet(pkt, iph);
#ifdef FEAT_IPV6
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        l3_header_len = parse_ipv6_packet(skb, pkt, TC_SKB_L3_OFF);
#endif
    } else {
        return TC_ACT_UNSPEC;
    }

    if (l3_header_len < 0) {
        return TC_ACT_SHOT;
    }

    if (pkt->frag_type != FRAG_NONE && pkt->frag_off != 0) {
        // not the first fragment
        pkt->l4_off = -1;
        return TC_ACT_OK;
    }
    pkt->l4_off = TC_SKB_L3_OFF + l3_header_len;
    pkt->err_l4_off = -1;

    if (pkt->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_PULL(skb, &tcph, pkt->l4_off, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pkt->tuple.sport = tcph->source;
        pkt->tuple.dport = tcph->dest;
    } else if (pkt->nexthdr == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_PULL(skb, &udph, pkt->l4_off, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pkt->tuple.sport = udph->source;
        pkt->tuple.dport = udph->dest;
    } else if (is_icmpx(pkt->nexthdr)) {
        struct icmphdr *icmph;
        if (VALIDATE_PULL(skb, &icmph, pkt->l4_off, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }
        int ret = icmpx_msg_type(IS_IPV4(pkt), pkt->nexthdr, icmph);
        switch (ret) {
        case ICMP_ERROR_MSG: {
            struct inet_tuple err_tuple = {};
            int err_l3_hdr_len;
            ret = parse_packet_light(
                skb, IS_IPV4(pkt), icmpx_err_l3_offset(pkt->l4_off), &err_tuple,
                &pkt->nexthdr, &err_l3_hdr_len);
            if (ret != TC_ACT_OK) {
                return ret;
            }
            pkt->err_l4_off = icmpx_err_l3_offset(pkt->l4_off) + err_l3_hdr_len;
            bpf_log_trace(
                "ICMP error nexthdr:%d, %pI4->%pI4, %pI4->%pI4, %d->%d",
                pkt->nexthdr, &pkt->tuple.saddr.ip, &pkt->tuple.daddr.ip,
                &err_tuple.saddr.ip, &err_tuple.daddr.ip,
                bpf_ntohs(err_tuple.sport), bpf_ntohs(err_tuple.dport));

            if (!ADDR6_EQ(pkt->tuple.daddr.all, err_tuple.saddr.all)) {
                bpf_log_error("IP destination address does not match source "
                              "address inside ICMP error message");
                return TC_ACT_SHOT;
            }

            COPY_ADDR6(pkt->tuple.saddr.all, err_tuple.daddr.all);
            pkt->tuple.sport = err_tuple.dport;
            pkt->tuple.dport = err_tuple.sport;
            break;
        }
        case ICMP_QUERY_MSG: {
            pkt->tuple.sport = pkt->tuple.dport = get_icmpx_query_id(icmph);
            bpf_log_debug("ICMP query, id:%d", bpf_ntohs(pkt->tuple.sport));
            break;
        }
        case ICMP_ACT_UNSPEC:
            return TC_ACT_UNSPEC;
        default:
            bpf_log_error("icmp shot");
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static int frag_timer_cb(void *_map_frag_track, struct map_frag_track_key *key,
                         struct bpf_timer *timer) {
#define BPF_LOG_TOPIC "fragment_track"
    bpf_log_trace("fragmentation tracking timeout, deleting");
    bpf_map_delete_elem(&map_frag_track, key);
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline int fragment_track(struct __sk_buff *skb,
                                          struct packet_info *pkt, u8 flags) {
#define BPF_LOG_TOPIC "fragment_track"

    if (pkt->frag_type == FRAG_NONE ||
        pkt->frag_type == FRAG_LAST && pkt->frag_off == 0) {
        // this is an atomic packet
        return pkt->l4_off >= 0 ? TC_ACT_OK : TC_ACT_UNSPEC;
    }
    if (is_icmpx_error_pkt(pkt)) {
        return TC_ACT_SHOT;
    }

    int ret;
    struct map_frag_track_key key = {
        .ifindex = skb->ifindex,
        .flags = (IS_IPV4(pkt) ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG) | flags,
        .l4proto = pkt->nexthdr,
        .id = pkt->frag_id,
        .saddr = pkt->tuple.saddr,
        .daddr = pkt->tuple.daddr,
    };

    struct map_frag_track_value *value;
    if (pkt->frag_type == FRAG_MORE && pkt->l4_off >= 0) {
        struct map_frag_track_value value_new = {
            .sport = pkt->tuple.sport,
            .dport = pkt->tuple.dport,
        };

        ret = bpf_map_update_elem(&map_frag_track, &key, &value_new, BPF_ANY);
        if (ret) {
            return TC_ACT_SHOT;
        }
        value = bpf_map_lookup_elem(&map_frag_track, &key);
        if (!value) {
            return TC_ACT_SHOT;
        }
        ret = bpf_timer_init(&value->timer, &map_frag_track, 0);
        if (ret) {
            goto delete_entry;
        }
        ret = bpf_timer_set_callback(&value->timer, frag_timer_cb);
        if (ret) {
            goto delete_entry;
        }
    } else {
        value = bpf_map_lookup_elem(&map_frag_track, &key);
        if (!value) {
            bpf_log_warn(
                "fragmentation session of this packet was not tracked");
            return TC_ACT_SHOT;
        }
        pkt->tuple.sport = value->sport;
        pkt->tuple.dport = value->dport;
    }

    ret = bpf_timer_start(&value->timer, TIMEOUT_FRAGMENT, 0);
    if (ret) {
        goto delete_entry;
    }

    return TC_ACT_OK;
delete_entry:
    bpf_log_error("setup timer err: %d", ret);
    bpf_map_delete_elem(&map_frag_track, &key);
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

static __always_inline struct dest_config *
lookup_dest_config(bool is_ipv4, const union u_inet_addr *external_addr) {
    if (is_ipv4) {
        struct ipv4_lpm_key key = {.prefixlen = 32, .ip = external_addr->ip};
        return bpf_map_lookup_elem(&map_ipv4_dest_config, &key);
    } else {
#ifdef FEAT_IPV6
        struct ipv6_lpm_key key;
        key.prefixlen = 128;
        COPY_ADDR6(key.ip6, external_addr->ip6);
        return bpf_map_lookup_elem(&map_ipv6_dest_config, &key);
#else
        return NULL;
#endif
    }
}

static __always_inline bool dest_hairpin(struct dest_config *config) {
    return config->flags & DEST_HAIRPIN_FLAG;
}
static __always_inline bool dest_pass_nat(struct dest_config *config) {
    return config->flags & DEST_NO_SNAT_FLAG;
}

static __always_inline struct external_config *
lookup_external_config(bool is_ipv4, const union u_inet_addr *external_addr) {
    struct external_config *config;
    if (is_ipv4) {
        struct ipv4_lpm_key key = {.prefixlen = 32, .ip = external_addr->ip};
        return bpf_map_lookup_elem(&map_ipv4_external_config, &key);
    } else {
#ifdef FEAT_IPV6
        struct ipv6_lpm_key key;
        key.prefixlen = 128;
        COPY_ADDR6(key.ip6, external_addr->ip6);
        return bpf_map_lookup_elem(&map_ipv6_external_config, &key);
#else
        return NULL;
#endif
    }
}

static __always_inline bool external_invalid(struct external_config *config) {
    return config->flags & EXTERNAL_DELETING_FLAG;
}
static __always_inline bool external_pass_nat(struct external_config *config) {
    return config->flags & EXTERNAL_NO_SNAT_FLAG;
}
static __always_inline int
nat_check_external_config(struct external_config *config) {
    if (!config || external_pass_nat(config))
        return TC_ACT_UNSPEC;
    if (external_invalid(config))
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}

static __always_inline bool nat_in_binding_range(struct external_config *config,
                                                 u8 nexthdr, u16 ext_port) {
    struct port_range *proto_range;
    u8 range_len = select_port_range(config, nexthdr, &proto_range);
    if (range_len >= 0 &&
        find_port_range_idx(ext_port, range_len, proto_range) >= 0) {
        return true;
    }
    return false;
}

static __always_inline void ipv4_update_csum(struct __sk_buff *skb,
                                             u32 l4_csum_off, __be32 from_addr,
                                             __be16 from_port, __be32 to_addr,
                                             __be16 to_port, bool l4_pseudo,
                                             bool l4_mangled_0) {
    bpf_l4_csum_replace(skb, l4_csum_off, from_port, to_port,
                        2 | (l4_mangled_0 ? BPF_F_MARK_MANGLED_0 : 0));
    if (l4_pseudo) {
        bpf_l4_csum_replace(skb, l4_csum_off, from_addr, to_addr,
                            4 | BPF_F_PSEUDO_HDR |
                                (l4_mangled_0 ? BPF_F_MARK_MANGLED_0 : 0));
    }
}

static __always_inline void
ipv4_update_csum_inner(struct __sk_buff *skb, u32 l4_csum_off, __be32 from_addr,
                       __be16 from_port, __be32 to_addr, __be16 to_port,
                       bool l4_pseudo, bool l4_mangled_0) {
    u16 csum;
    if (l4_mangled_0) {
        bpf_skb_load_bytes(skb, l4_csum_off, &csum, sizeof(csum));
    }
    if (!l4_mangled_0 || csum != 0) {
        // use bpf_l3_csum_replace to avoid updating skb csum
        bpf_l3_csum_replace(skb, l4_csum_off, from_port, to_port, 2);

        if (l4_pseudo) {
            bpf_l3_csum_replace(skb, l4_csum_off, from_addr, to_addr, 4);
        }
    }
}

static __always_inline void ipv4_update_csum_icmp_err(
    struct __sk_buff *skb, u32 icmp_csum_off, u32 err_ip_check_off,
    u32 err_l4_csum_off, __be32 from_addr, __be16 from_port, __be32 to_addr,
    __be16 to_port, bool icmp_pseudo, bool err_l4_pseudo, bool l4_mangled_0) {

    u16 prev_csum;
    u16 curr_csum;
    bpf_skb_load_bytes(skb, err_ip_check_off, &prev_csum, sizeof(prev_csum));

    bpf_l3_csum_replace(skb, err_ip_check_off, from_addr, to_addr, 4);

    bpf_skb_load_bytes(skb, err_ip_check_off, &curr_csum, sizeof(curr_csum));
    bpf_l4_csum_replace(skb, icmp_csum_off, prev_csum, curr_csum, 2);

    // update of inner message
#if 1
    // the update of embedded layer 4 checksum is not required but may helpful
    // for packet tracking
    // the TCP checksum might not be included in IPv4 packet, check if it exist
    // first
    if (bpf_skb_load_bytes(skb, err_l4_csum_off, &prev_csum,
                           sizeof(prev_csum))) {
        ipv4_update_csum_inner(skb, err_l4_csum_off, from_addr, from_port,
                               to_addr, to_port, err_l4_pseudo, l4_mangled_0);

        bpf_skb_load_bytes(skb, err_l4_csum_off, &curr_csum, sizeof(curr_csum));
        bpf_l4_csum_replace(skb, icmp_csum_off, prev_csum, curr_csum, 2);
    }
#endif
    bpf_l4_csum_replace(skb, icmp_csum_off, from_addr, to_addr, 4);
    bpf_l4_csum_replace(skb, icmp_csum_off, from_port, to_port, 2);

    if (icmp_pseudo) {
        bpf_l4_csum_replace(skb, icmp_csum_off, from_addr, to_addr,
                            4 | BPF_F_PSEUDO_HDR);
    }
}

static __always_inline struct map_binding_value *
insert_new_binding(const struct map_binding_key *key,
                   const struct map_binding_value *val,
                   struct map_binding_value **lk_val_rev) {
#define BPF_LOG_TOPIC "insert_new_binding"
    int ret;
    struct map_binding_key key_rev;
    get_rev_dir_binding_key(key, val, &key_rev);

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
    get_rev_dir_binding_key(&b_key, b_value, &b_key_orig);

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
        goto delete_ct;
    }
    ret = bpf_timer_set_callback(&value->timer, ct_timer_cb);
    if (ret) {
        goto delete_ct;
    }
    ret = bpf_timer_start(&value->timer, 30E9, 0);
    if (ret) {
        goto delete_ct;
    }

    return value;
delete_ct:
    bpf_log_error("setup timer err:%d", ret);
    bpf_map_delete_elem(&map_ct, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

static __always_inline int
modify_headers(struct __sk_buff *skb, bool is_ipv4, bool is_icmpx_error,
               u8 nexthdr, int l3_off, int l4_off, int err_l4_off,
               bool is_modify_source, union u_inet_addr *from_addr,
               __be16 from_port, union u_inet_addr *to_addr, __be16 to_port) {
    int ret;
    ret = bpf_write_inet_addr(
        skb, is_ipv4, l3_off + get_l3_to_addr_off(is_ipv4, is_modify_source),
        to_addr);
    if (ret) {
        return ret;
    }
    if (is_ipv4) {
        ret = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
                                  from_addr->ip, to_addr->ip, 4);
        if (ret) {
            return ret;
        }
    }
    if (l4_off < 0) {
        return 0;
    }

    int l4_to_port_off;
    int l4_to_check_off;
    bool l4_check_pseudo;
    bool l4_check_mangle_0;
    switch (nexthdr) {
    case IPPROTO_TCP:
        l4_to_port_off = is_modify_source ^ is_icmpx_error
                             ? offsetof(struct tcphdr, source)
                             : offsetof(struct tcphdr, dest);
        l4_to_check_off = offsetof(struct tcphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = false;
        break;
    case IPPROTO_UDP:
        l4_to_port_off = is_modify_source ^ is_icmpx_error
                             ? offsetof(struct udphdr, source)
                             : offsetof(struct udphdr, dest);
        l4_to_check_off = offsetof(struct udphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = is_ipv4;
        break;
    case IPPROTO_ICMP:
#ifdef FEAT_IPV6
    case NEXTHDR_ICMP:
#endif
        l4_to_port_off = offsetof(struct icmphdr, un.echo.id);
        l4_to_check_off = offsetof(struct icmphdr, checksum);
#ifdef FEAT_IPV6
        l4_check_pseudo = nexthdr == NEXTHDR_ICMP;
#else
        l4_check_pseudo = false;
#endif
        l4_check_mangle_0 = false;
        break;
    default:
        return 1;
    }

    if (is_icmpx_error) {
        ret = bpf_write_inet_addr(
            skb, is_ipv4,
            icmpx_err_l3_offset(l4_off) +
                get_l3_to_addr_off(is_ipv4, !is_modify_source),
            to_addr);
        if (ret) {
            return ret;
        }
    }

    ret = bpf_write_port(
        skb, (is_icmpx_error ? err_l4_off : l4_off) + l4_to_port_off, to_port);
    if (ret) {
        return ret;
    }

    // TODO: handle IPv6
    if (is_icmpx_error) {
        ipv4_update_csum_icmp_err(
            skb, l4_off + offsetof(struct icmphdr, checksum),
            icmpx_err_l3_offset(l4_off) + offsetof(struct iphdr, check),
            err_l4_off + l4_to_check_off, from_addr->ip, from_port, to_addr->ip,
            to_port, !is_ipv4, l4_check_pseudo, l4_check_mangle_0);
    } else {
        ipv4_update_csum(skb, l4_off + l4_to_check_off, from_addr->ip,
                         from_port, to_addr->ip, to_port, l4_check_pseudo,
                         l4_check_mangle_0);
    }

    return 0;
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
    u16 orig_port;
    struct port_range range;
    int curr_remaining;
    u16 curr_port;
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

static int __always_inline fill_unique_binding_port(
    bool val_is_ipv4, u8 l4proto, const struct map_binding_key *key_orig,
    struct map_binding_value *val_orig) {
#define BPF_LOG_TOPIC "find_binding_port"
    int ret;
    struct external_config *ext_config =
        lookup_external_config(val_is_ipv4, &val_orig->to_addr);
    if ((ret = nat_check_external_config(ext_config)) != TC_ACT_OK) {
        return ret;
    }

    struct port_range *proto_range;
    u8 range_len = select_port_range(ext_config, l4proto, &proto_range);
    if (range_len == 0) {
        return TC_ACT_SHOT;
    }
    if (range_len > MAX_PORT_RANGES) {
        range_len = MAX_PORT_RANGES;
    }

    struct find_port_ctx ctx;

    get_rev_dir_binding_key(key_orig, val_orig, &ctx.key);
    ctx.orig_port = bpf_ntohs(key_orig->from_port);
    ctx.curr_port = bpf_ntohs(ctx.key.from_port);
    ctx.found = false;

    int start_range_idx =
        find_port_range_idx(ctx.curr_port, range_len, proto_range);
    if (start_range_idx < 0) {
        start_range_idx = bpf_get_prandom_u32() % range_len;
    }

#pragma unroll
    for (int i = 0; i < MAX_PORT_RANGES; i++) {
        if (i >= range_len) {
            break;
        }
        u32 idx = ((start_range_idx + i) % range_len) & MAX_PORT_RANGES;
        ctx.range = proto_range[idx];
        ctx.curr_remaining = ctx.range.end_port - ctx.range.begin_port + 1;
        if (ctx.curr_remaining <= 0) {
            continue;
        }
        if (ctx.curr_port < ctx.range.begin_port ||
            ctx.curr_port > ctx.range.end_port) {
            ctx.curr_port = (bpf_get_prandom_u32() % ctx.curr_remaining) +
                            ctx.range.begin_port;
        }

        bpf_loop(65536, find_port_cb, &ctx, 0);
        if (ctx.found) {
            val_orig->to_port = ctx.key.from_port;
            return TC_ACT_OK;
        }
    }

    bpf_log_warn("out of binding port");
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

static __always_inline int egress_lookup_or_new_binding(
    u32 ifindex, bool is_ipv4, u8 l4proto, bool is_icmpx_error,
    const struct inet_tuple *origin, struct map_binding_value **b_value_,
    struct map_binding_value **b_value_rev_) {
    struct map_binding_key b_key = {
        .ifindex = ifindex,
        .flags =
            BINDING_ORIG_DIR_FLAG | (is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG),
        .l4proto = l4proto,
        .from_port = origin->sport,
        .from_addr = origin->saddr,
    };

    struct map_binding_value *b_value_rev = NULL;
    struct map_binding_value *b_value =
        bpf_map_lookup_elem(&map_binding, &b_key);
    if (!b_value) {
        if (is_icmpx_error) {
            return TC_ACT_SHOT;
        }
        // XXX: do NAT64 if origin->daddr has NAT64 prefix
        bool nat_x_4 = is_ipv4;
        struct map_binding_value b_value_new;
        b_value_new.flags = (nat_x_4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG);
        b_value_new.to_port = b_key.from_port;
        b_value_new.is_static = false;
        b_value_new.use = 0;
        b_value_new.ref = 0;
        if (nat_x_4) {
            inet_addr_set_ip(&b_value_new.to_addr, g_ipv4_external_addr);
        } else {
            // TODO: handle IPv6
        }

        int ret =
            fill_unique_binding_port(nat_x_4, l4proto, &b_key, &b_value_new);
        if (ret != TC_ACT_OK) {
            return ret;
        }

        b_value = insert_new_binding(&b_key, &b_value_new, &b_value_rev);
        if (!(b_value && b_value_rev)) {
            return TC_ACT_SHOT;
        }
    }
    *b_value_ = b_value;
    *b_value_rev_ = b_value_rev;

    return TC_ACT_OK;
}

static __always_inline struct map_ct_value *
egress_lookup_or_new_ct(u32 ifindex, bool is_ipv4, u8 l4proto,
                        bool is_icmpx_error, const struct inet_tuple *origin,
                        struct map_binding_value *b_value,
                        struct map_binding_value *b_value_rev) {
#define BPF_LOG_TOPIC "egress_lookup_or_new_ct"

#define ENSURE_REV_BINDING()                                                   \
    ({                                                                         \
        if (!b_value_rev) {                                                    \
            struct map_binding_key b_key_rev;                                  \
            binding_value_to_key(ifindex, 0, l4proto, b_value, &b_key_rev);    \
            b_value_rev = bpf_map_lookup_elem(&map_binding, &b_key_rev);       \
            if (!b_value_rev) {                                                \
                return NULL;                                                   \
            }                                                                  \
        }                                                                      \
    })

    struct map_ct_key ct_key;
    ct_key.ifindex = ifindex;
    ct_key.flags =
        FLAGS_IS_IPV4(b_value->flags) ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG;
    ct_key.l4proto = l4proto;
    ct_key._pad = 0;
    COPY_ADDR6(ct_key.external.saddr.all, b_value->to_addr.all);
    ct_key.external.sport = b_value->to_port;
    // XXX: do NAT64 if origin is IPv6 and b_value->flags contains
    // ADDR_IPV4_FLAG
    COPY_ADDR6(ct_key.external.daddr.all, origin->daddr.all);
    ct_key.external.dport = origin->dport;

    struct map_ct_value *ct_value = bpf_map_lookup_elem(&map_ct, &ct_key);
    if (!ct_value) {
        if (is_icmpx_error) {
            return NULL;
        }
        ENSURE_REV_BINDING();

        struct map_ct_value ct_value_new = {
            .flags = is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG,
            .origin = *origin,
            .state = CT_ESTABLISHED,
        };
        ct_value = insert_new_ct(&ct_key, &ct_value_new);
        if (!ct_value) {
            return NULL;
        }

        // TODO: separate out state transition logics
        __sync_fetch_and_add(&b_value_rev->ref, 1);
        __sync_fetch_and_add(&b_value_rev->use, 1);

        bpf_log_debug("insert new CT");
    } else if (!is_icmpx_error && ct_value->state == CT_IN_ONLY) {
        ENSURE_REV_BINDING();
        // XXX: use lock?
        ct_value->state = CT_ESTABLISHED;
        __sync_fetch_and_add(&b_value_rev->use, 1);

        bpf_log_debug("found existing inbound initialized CT");
    }
#undef ENSURE_REV_BINDING

    return ct_value;
#undef BPF_LOG_TOPIC
}

static __always_inline int
ingress_lookup_or_new_ct(u32 ifindex, bool is_ipv4, u8 l4proto,
                         bool is_icmpx_error, const struct inet_tuple *reply,
                         struct map_ct_value **ct_value_) {
#define BPF_LOG_TOPIC "ingress_lookup_or_new_ct"
    struct map_ct_key ct_key;
    ct_key.ifindex = ifindex;
    ct_key.flags = is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG;
    ct_key.l4proto = l4proto;
    ct_key._pad = 0;
    inet_tuple_rev_copy(&ct_key.external, reply);

    struct map_ct_value *ct_value = bpf_map_lookup_elem(&map_ct, &ct_key);
    if (!ct_value) {
        if (is_icmpx_error) {
            return TC_ACT_SHOT;
        }
        struct map_binding_key b_key = {
            .ifindex = ifindex,
            .flags = is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG,
            .l4proto = l4proto,
            .from_port = reply->dport,
            .from_addr = reply->daddr,
        };

        struct map_binding_value *b_value =
            bpf_map_lookup_elem(&map_binding, &b_key);
        if (!b_value && is_icmpx(l4proto) && !is_icmpx_error) {
            // TODO: always create new binding & CT for inbound ICMP query
            // messages like pings to local NAT host, also allow refreshing
            // CT from inbound
        }
        if (!b_value || __sync_fetch_and_add(&b_value->use, 0) == 0) {
            // TODO: add to pending conntrack table if no mapping
            // TODO: delay and send back ICMP port unreachable
            bpf_log_debug("mapping not active");
            return TC_ACT_SHOT;
        }
        if (b_value->is_static) {
            return TC_ACT_UNSPEC;
        }

        struct map_ct_value ct_value_new;
        ct_value_new.flags =
            FLAGS_IS_IPV4(b_value->flags) ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG;
        ct_value_new.state = CT_IN_ONLY;
        ct_value_new.last_seen = 0;
        COPY_ADDR6(ct_value_new.origin.saddr.all, b_value->to_addr.all);
        ct_value_new.origin.sport = b_value->to_port;
        // XXX: do reverse NAT64 (i.e. append NAT64 prefix) if reply is IPv4 and
        // b_value->flags contains ADDR_IPV6_FLAG
        COPY_ADDR6(ct_value_new.origin.daddr.all, reply->saddr.all);
        ct_value_new.origin.dport = reply->sport;

        ct_value = insert_new_ct(&ct_key, &ct_value_new);
        if (!ct_value) {
            return TC_ACT_SHOT;
        }
        __sync_fetch_and_add(&b_value->ref, 1);

        bpf_log_debug("insert new CT");
    } else if (ct_value->state == CT_IN_ONLY) {
        struct map_binding_key b_key = {
            .ifindex = ifindex,
            .flags = is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG,
            .l4proto = l4proto,
            .from_port = reply->dport,
            .from_addr = reply->daddr,
        };

        struct map_binding_value *b_value =
            bpf_map_lookup_elem(&map_binding, &b_key);
        if (!b_value) {
            return TC_ACT_SHOT;
        }
        if (b_value->is_static) {
            return TC_ACT_UNSPEC;
        }

        if (__sync_fetch_and_add(&b_value->use, 0) != 0) {
            bpf_log_error("refresh CT");
            bpf_timer_start(&ct_value->timer, 30E9, 0);
        }
    }

    *ct_value_ = ct_value;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc") int ingress_rev_snat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "ingress<=="
    int ret;
    struct packet_info pkt;

    ret = parse_packet(skb, &pkt);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }
    if (pkt.nexthdr != IPPROTO_UDP && !is_icmpx(pkt.nexthdr) ||
        !IS_IPV4(&pkt)) {
        return TC_ACT_UNSPEC;
    }

    struct dest_config *dest_config =
        lookup_dest_config(IS_IPV4(&pkt), &pkt.tuple.saddr);
    if (dest_config && dest_pass_nat(dest_config)) {
        return TC_ACT_UNSPEC;
    }

    if ((ret = fragment_track(skb, &pkt, 0)) != TC_ACT_OK) {
        return ret;
    }

    struct external_config *ext_config =
        lookup_external_config(IS_IPV4(&pkt), &pkt.tuple.daddr);
    if ((ret = nat_check_external_config(ext_config)) != TC_ACT_OK) {
        return ret;
    }
    if (!nat_in_binding_range(ext_config, pkt.nexthdr,
                              bpf_ntohs(pkt.tuple.dport))) {
        return TC_ACT_UNSPEC;
    }

    bool is_icmpx_error = is_icmpx_error_pkt(&pkt);
    struct map_ct_value *ct_value;
    ret = ingress_lookup_or_new_ct(skb->ifindex, IS_IPV4(&pkt), pkt.nexthdr,
                                   is_icmpx_error, &pkt.tuple, &ct_value);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    // modify dest
    ret = modify_headers(skb, IS_IPV4(&pkt), is_icmpx_error, pkt.nexthdr,
                         TC_SKB_L3_OFF, pkt.l4_off, pkt.err_l4_off, false,
                         &pkt.tuple.daddr, pkt.tuple.dport,
                         &ct_value->origin.saddr, ct_value->origin.sport);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int egress_snat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "egress ==>"
    int ret;
    struct packet_info pkt;

    ret = parse_packet(skb, &pkt);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }
    if (pkt.nexthdr != IPPROTO_UDP && !is_icmpx(pkt.nexthdr) ||
        !IS_IPV4(&pkt)) {
        return TC_ACT_UNSPEC;
    }

    bool do_hairpin = false;
    struct dest_config *dest_config =
        lookup_dest_config(IS_IPV4(&pkt), &pkt.tuple.saddr);
    if (dest_config) {
        do_hairpin = dest_hairpin(dest_config);
        if (dest_pass_nat(dest_config)) {
            goto check_hairpin;
        }
    }

    if ((ret = fragment_track(skb, &pkt, FRAG_TRACK_EGRESS_FLAG)) !=
        TC_ACT_OK) {
        if (ret == TC_ACT_UNSPEC) {
            goto check_hairpin;
        }
        return ret;
    }

    struct external_config *ext_config =
        lookup_external_config(IS_IPV4(&pkt), &pkt.tuple.saddr);
    if (ext_config) { // this packet was send from local NAT host
        if (external_pass_nat(ext_config)) {
            goto check_hairpin;
        }
        if (external_invalid(ext_config)) {
            return TC_ACT_SHOT;
        }
        if (!nat_in_binding_range(ext_config, pkt.nexthdr,
                                  bpf_ntohs(pkt.tuple.dport))) {
            goto check_hairpin;
        }

        // SNAT from external IP to itself, i.e. do
        // binding of
        // <external IP>:<host port> -> <external IP>:<external port>.
        //
        // Note ICMP query ID remapping for external IP is always needed as
        // Linux allows setting arbitrary ICMP ID which could causing
        // collision with ICMP ID binding of other internal source.
    }

    bool is_icmpx_error = is_icmpx_error_pkt(&pkt);
    struct map_binding_value *b_value, *b_value_rev;
    ret = egress_lookup_or_new_binding(skb->ifindex, IS_IPV4(&pkt), pkt.nexthdr,
                                       is_icmpx_error, &pkt.tuple, &b_value,
                                       &b_value_rev);
    if (ret == TC_ACT_UNSPEC) {
        return TC_ACT_UNSPEC;
    } else if (ret != TC_ACT_OK) {
        // XXX: no free port, send back ICMP network unreachable
        return TC_ACT_SHOT;
    }

    if (!b_value->is_static) {
        struct map_ct_value *ct_value = egress_lookup_or_new_ct(
            skb->ifindex, IS_IPV4(&pkt), pkt.nexthdr, is_icmpx_error,
            &pkt.tuple, b_value, b_value_rev);
        if (!ct_value) {
            return TC_ACT_SHOT;
        }
        bpf_timer_start(&ct_value->timer, 300E9, 0);
    }

    // modify source
    ret = modify_headers(skb, IS_IPV4(&pkt), is_icmpx_error, pkt.nexthdr,
                         TC_SKB_L3_OFF, pkt.l4_off, pkt.err_l4_off, true,
                         &pkt.tuple.saddr, pkt.tuple.sport, &b_value->to_addr,
                         b_value->to_port);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

check_hairpin:
    if (do_hairpin) {
        // TODO: redirect to ingress
    }
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

char _license[] SEC("license") = "GPL";
