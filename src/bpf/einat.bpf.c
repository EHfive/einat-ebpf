// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#include "einat.h"

#define DEFAULT_FRAG_TRACK_MAX_ENTRIES 65536
#define DEFAULT_BINDING_MAX_ENTRIES (65536 * 3 * 2)
#define DEFAULT_CONNTRACK_MAX_ENTRIES DEFAULT_BINDING_MAX_ENTRIES

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;

// Bare IP packet if false
const volatile u8 HAS_ETH_ENCAP = true;

const volatile u8 INGRESS_IPV4 = true;
const volatile u8 EGRESS_IPV4 = true;

// These are acted as paddings if not FEAT_IPV6
const volatile u8 INGRESS_IPV6 = true;
const volatile u8 EGRESS_IPV6 = true;

// Lookup external source address from FIB instead of using
// g_ipv4_external_addr, requires Linux kernel>=6.7
const volatile u8 ENABLE_FIB_LOOKUP_SRC = false;

// Allow inbound initiated binding towards local NAT host for ICMP query
// message.
// This could cause the NAT running out of ICMP IDs if
// an attacker is flooding ICMP packets of all ICMP IDs(0-65536) to NAT host,
// causing internal hosts behind NAT failed to create new binding hence
// resulting network disconnection for ICMP.
// Thus we have introduced additional configurations of ICMP ID mapping range
// for inbound and outbound directions respectively, so we can limit how much
// ICMP IDs can be mapped.
const volatile u8 ALLOW_INBOUND_ICMPX = true;

// at least FRAGMENT_MIN=2s,
// https://datatracker.ietf.org/doc/html/rfc6146#section-4
const volatile u64 TIMEOUT_FRAGMENT = 2E9;

const volatile u64 TIMEOUT_PKT_MIN = 120E9;
const volatile u64 TIMEOUT_PKT_DEFAULT = 300E9;

// https://datatracker.ietf.org/doc/html/rfc6146#section-4
const volatile u64 TIMEOUT_TCP_TRANS = 240E9;
const volatile u64 TIMEOUT_TCP_EST = 7440E9;

__be32 g_ipv4_external_addr SEC(".data") = 0;
#ifdef FEAT_IPV6
__be32 g_ipv6_external_addr[4] SEC(".data") = {0};
#endif

u8 g_deleting_map_entries SEC(".data") = 0;

u32 g_next_binding_seq = 0;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

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
    __uint(map_flags, BPF_F_NO_PREALLOC);
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

enum {
    PKT_CONNLESS,
    PKT_TCP_DATA,
    PKT_TCP_SYN,
    PKT_TCP_RST,
    PKT_TCP_FIN,
};

enum { FRAG_NONE, FRAG_MORE, FRAG_LAST };

struct packet_info {
#ifdef FEAT_IPV6
    bool is_ipv4;
#endif
    // `nexthdr` and `tuple` fields reflect embedded ICMP error IP packet in the
    // case of ICMP error message, otherwise reflect TCP, UDP or ICMP query
    // message.
    u8 nexthdr;
    u8 pkt_type;
    u8 frag_type;
    u16 frag_off;
    u32 frag_id;
    struct inet_tuple tuple;
    int l4_off;
    // ICMP error message
    int err_l4_off;
};

#define TC_SKB_L3_OFF() (HAS_ETH_ENCAP ? sizeof(struct ethhdr) : 0)

#ifdef FEAT_IPV6
#define IS_IPV4(pkt) ((pkt)->is_ipv4)
#define FLAGS_IS_IPV4(flags) ((flags) & ADDR_IPV4_FLAG)
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

static __always_inline bool pkt_allow_initiating_ct(u8 pkt_type) {
    return pkt_type == PKT_CONNLESS || pkt_type == PKT_TCP_SYN;
}

static __always_inline int parse_ipv4_packet_light(const struct iphdr *iph,
                                                   struct inet_tuple *tuple,
                                                   u8 *nexthdr, u32 *len_) {
#define BPF_LOG_TOPIC "parse_ipv4_packet_light"
    if (iph->version != 4) {
        return TC_ACT_SHOT;
    }
    inet_addr_set_ip(&tuple->saddr, iph->saddr);
    inet_addr_set_ip(&tuple->daddr, iph->daddr);
    *nexthdr = iph->protocol;
    if (iph->frag_off & bpf_htons(IP_OFFSET)) {
        return TC_ACT_SHOT;
    }
    *len_ = iph->ihl * 4;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
parse_ipv4_packet(struct packet_info *pkt, const struct iphdr *iph, u32 *len_) {
#define BPF_LOG_TOPIC "parse_ipv4_packet"
    if (iph->version != 4) {
        return TC_ACT_SHOT;
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
    *len_ = iph->ihl * 4;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#ifdef FEAT_IPV6
static __always_inline int
_parse_ipv6_packet(struct __sk_buff *skb, u32 l3_off, struct inet_tuple *tuple,
                   u8 *nexthdr_, struct frag_hdr *frag_hdr, u32 *len_) {
#define BPF_LOG_TOPIC "_parse_ipv6_packet"
    struct ipv6hdr *ip6h;
    if (VALIDATE_PULL(skb, &ip6h, l3_off, sizeof(*ip6h))) {
        return TC_ACT_SHOT;
    }
    if (ip6h->version != 6) {
        return TC_ACT_SHOT;
    }
    inet_addr_set_ip6(&tuple->saddr, ip6h->saddr.in6_u.u6_addr32);
    inet_addr_set_ip6(&tuple->daddr, ip6h->daddr.in6_u.u6_addr32);

    int len = sizeof(struct ipv6hdr);
    u32 frag_hdr_off = 0;
    u8 nexthdr = ip6h->nexthdr;
    struct ipv6_opt_hdr opthdr;

    // XXX: this loop results enormous verification time
    // MAX_IPV6_EXT_NUM minus one of auth header
#pragma unroll
    for (int i = 0; i < MAX_IPV6_EXT_NUM - 1; i++) {
        switch (nexthdr) {
        case NEXTHDR_AUTH:
            // Just passthrough IPSec packet
            return TC_ACT_UNSPEC;
        case NEXTHDR_FRAGMENT:
            frag_hdr_off = len;
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST: {
            if (bpf_skb_load_bytes(skb, l3_off + len, &opthdr,
                                   sizeof(opthdr))) {
                return TC_ACT_SHOT;
            }
            len += (opthdr.hdrlen + 1) * 8;
            nexthdr = opthdr.nexthdr;
            break;
        }
        default:
            goto found_upper_layer;
        }
    }

    switch (nexthdr) {
    case NEXTHDR_TCP:
    case NEXTHDR_UDP:
    case NEXTHDR_ICMP:
        goto found_upper_layer;
    default:
        return TC_ACT_UNSPEC;
    }

found_upper_layer:
    if (frag_hdr_off) {
        if (bpf_skb_load_bytes(skb, l3_off + frag_hdr_off, frag_hdr,
                               sizeof(*frag_hdr))) {
            return TC_ACT_SHOT;
        }
    } else {
        frag_hdr->nexthdr = 0;
        frag_hdr->reserved = 0;
        frag_hdr->frag_off = 0;
        frag_hdr->identification = 0;
    }

    *nexthdr_ = nexthdr;
    *len_ = len;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int parse_ipv6_packet_light(struct __sk_buff *skb,
                                                   u32 l3_off,
                                                   struct inet_tuple *tuple,
                                                   u8 *nexthdr, u32 *len_) {
#define BPF_LOG_TOPIC "parse_ipv6_packet_light"

    struct frag_hdr frag_hdr;
    int ret = _parse_ipv6_packet(skb, l3_off, tuple, nexthdr, &frag_hdr, len_);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    if (frag_hdr.frag_off & bpf_htons(IPV6_FRAG_OFFSET)) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int parse_ipv6_packet(struct __sk_buff *skb,
                                             struct packet_info *pkt,
                                             u32 l3_off, u32 *len_) {
#define BPF_LOG_TOPIC "parse_ipv6_packet"
    pkt->is_ipv4 = false;

    struct frag_hdr frag_hdr;
    int ret = _parse_ipv6_packet(skb, l3_off, &pkt->tuple, &pkt->nexthdr,
                                 &frag_hdr, len_);
    if (ret != TC_ACT_OK) {
        return ret;
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
    return TC_ACT_OK;
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
                                              bool is_ipv4, u32 l3_off,
                                              struct inet_tuple *tuple,
                                              u8 *nexthdr, u32 *l3_hdr_len) {
#define BPF_LOG_TOPIC "parse_packet_light"
    int ret;
    if (is_ipv4) {
        struct iphdr *iph;
        if (VALIDATE_PULL(skb, &iph, l3_off, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        ret = parse_ipv4_packet_light(iph, tuple, nexthdr, l3_hdr_len);
        if (ret != TC_ACT_OK) {
            return ret;
        }
    } else {
#ifdef FEAT_IPV6
        ret = parse_ipv6_packet_light(skb, l3_off, tuple, nexthdr,
                                      (u32 *)l3_hdr_len);
        if (ret != TC_ACT_OK) {
            return ret;
        }
#else
        return TC_ACT_UNSPEC;
#endif
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

static __always_inline int parse_packet(struct __sk_buff *skb, bool is_ipv4,
                                        u32 l3_off, struct packet_info *pkt) {
#define BPF_LOG_TOPIC "parse_packet"

    int ret;
    u32 l3_header_len;
    if (is_ipv4) {
        struct iphdr *iph;
        if (VALIDATE_PULL(skb, &iph, l3_off, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        ret = parse_ipv4_packet(pkt, iph, &l3_header_len);
        if (ret != TC_ACT_OK) {
            return TC_ACT_UNSPEC;
        }
    } else {
#ifdef FEAT_IPV6
        ret = parse_ipv6_packet(skb, pkt, l3_off, &l3_header_len);
        if (ret != TC_ACT_OK) {
            return TC_ACT_UNSPEC;
        }
#else
        return TC_ACT_UNSPEC;
#endif
    }

    pkt->pkt_type = PKT_CONNLESS;
    pkt->err_l4_off = -1;
    if (pkt->frag_type != FRAG_NONE && pkt->frag_off != 0) {
        // not the first fragment
        pkt->l4_off = -1;
        pkt->tuple.sport = 0;
        pkt->tuple.dport = 0;
        return TC_ACT_OK;
    }
    pkt->l4_off = l3_off + l3_header_len;

    if (pkt->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_PULL(skb, &tcph, pkt->l4_off, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pkt->tuple.sport = tcph->source;
        pkt->tuple.dport = tcph->dest;
        if (tcph->fin) {
            pkt->pkt_type = PKT_TCP_FIN;
        } else if (tcph->rst) {
            pkt->pkt_type = PKT_TCP_RST;
        } else if (tcph->syn) {
            pkt->pkt_type = PKT_TCP_SYN;
        } else {
            pkt->pkt_type = PKT_TCP_DATA;
        }
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
            u32 err_l3_hdr_len;
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

            if (!inet_addr_equal(&pkt->tuple.daddr, &err_tuple.saddr)) {
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
            bpf_log_trace("ICMP query, id:%d", bpf_ntohs(pkt->tuple.sport));
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
                         struct map_frag_track_value *_value) {
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
        (pkt->frag_type == FRAG_LAST && pkt->frag_off == 0)) {
        // this is an atomic packet
        // XXX: pkt->l4_off >= 0 is always true here
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

static __always_inline bool is_internal(struct external_config *config) {
    return config->flags & EXTERNAL_IS_INTERNAL_FLAG;
}

static __always_inline bool external_pass_nat(struct external_config *config) {
    return config->flags & EXTERNAL_NO_SNAT_FLAG;
}

static __always_inline int
nat_check_external_config(struct external_config *config) {
    if (!config || external_pass_nat(config))
        return TC_ACT_UNSPEC;
    if (is_internal(config)) {
        // internal should not be seen by external
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

static __always_inline bool nat_in_binding_range(struct external_config *config,
                                                 u8 nexthdr, u16 ext_port) {
    struct port_range *proto_range;
    u8 range_len = select_port_range(config, nexthdr, RANGE_ALL, &proto_range);
    if (find_port_range_idx(ext_port, range_len, proto_range) >= 0) {
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
    __be16 to_port, bool err_l4_pseudo, bool l4_mangled_0) {

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

    // the TCP checksum might not be included in IPv4
    // packet, check if it exists first
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
}

#ifdef FEAT_IPV6

static __always_inline void
ipv6_update_csum(struct __sk_buff *skb, u32 l4_csum_off, __be32 from_addr[4],
                 __be16 from_port, __be32 to_addr[4], __be16 to_port) {
    bpf_l4_csum_replace(skb, l4_csum_off, from_port, to_port, 2);
#pragma unroll
    for (int i = 0; i < 4; i++) {
        bpf_l4_csum_replace(skb, l4_csum_off, from_addr[i], to_addr[i],
                            4 | BPF_F_PSEUDO_HDR);
    }
}

static __always_inline void
ipv6_update_csum_inner(struct __sk_buff *skb, u32 l4_csum_off,
                       __be32 from_addr[4], __be16 from_port, __be32 to_addr[4],
                       __be16 to_port) {
    // use bpf_l3_csum_replace to avoid updating skb csum
    bpf_l3_csum_replace(skb, l4_csum_off, from_port, to_port, 2);

#pragma unroll
    for (int i = 0; i < 4; i++) {
        bpf_l3_csum_replace(skb, l4_csum_off, from_addr[i], to_addr[i], 4);
    }
}

static __always_inline void
ipv6_update_csum_icmp_err(struct __sk_buff *skb, u32 icmp_csum_off,
                          u32 err_l4_csum_off, __be32 from_addr[4],
                          __be16 from_port, __be32 to_addr[4], __be16 to_port) {
    // update of inner message
#if 1
    u16 prev_csum;
    u16 curr_csum;
    if (bpf_skb_load_bytes(skb, err_l4_csum_off, &prev_csum,
                           sizeof(prev_csum))) {

        ipv6_update_csum_inner(skb, err_l4_csum_off, from_addr, from_port,
                               to_addr, to_port);

        bpf_skb_load_bytes(skb, err_l4_csum_off, &curr_csum, sizeof(curr_csum));
        bpf_l4_csum_replace(skb, icmp_csum_off, prev_csum, curr_csum, 2);
    }
#endif

#pragma unroll
    for (int i = 0; i < 4; i++) {
        bpf_l4_csum_replace(skb, icmp_csum_off, from_addr[i], to_addr[i], 4);
    }
    bpf_l4_csum_replace(skb, icmp_csum_off, from_port, to_port, 2);

#pragma unroll
    for (int i = 0; i < 4; i++) {
        bpf_l4_csum_replace(skb, icmp_csum_off, from_addr[i], to_addr[i],
                            4 | BPF_F_PSEUDO_HDR);
    }
}

#endif

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
        .seq = val->seq,
    };
    ret = bpf_map_update_elem(&map_binding, key, val, BPF_ANY);
    if (ret) {
        bpf_log_error("failed to insert binding entry, err:%d", ret);
        goto error_update;
    }
    ret = bpf_map_update_elem(&map_binding, &key_rev, &val_rev, BPF_ANY);
    if (ret) {
        bpf_log_error("failed to insert reverse binding entry, err:%d", ret);
        goto error_update;
    }

    if (lk_val_rev) {
        *lk_val_rev = bpf_map_lookup_elem(&map_binding, &key_rev);
        if (!*lk_val_rev) {
            return NULL;
        }
    }

    return bpf_map_lookup_elem(&map_binding, key);
error_update:
    bpf_map_delete_elem(&map_binding, key);
    bpf_map_delete_elem(&map_binding, &key_rev);
    return NULL;
#undef BPF_LOG_TOPIC
}

static __always_inline void delete_ct(struct map_ct_key *key) {
#define BPF_LOG_TOPIC "delete_ct"
    struct map_binding_key b_key_rev = {
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

    struct map_binding_value *b_value_rev =
        bpf_map_lookup_elem(&map_binding, &b_key_rev);
    if (!b_value_rev || b_value_rev->seq != ct_value->seq) {
        goto delete_ct;
    }

    if (ct_value->state == CT_INIT_IN) {
        if (__sync_sub_and_fetch(&b_value_rev->ref, 1) != 0) {
            goto delete_ct;
        }
    } else if (__sync_sub_and_fetch(&b_value_rev->use, 1),
               __sync_sub_and_fetch(&b_value_rev->ref, 1) != 0) {
        goto delete_ct;
    }

    struct map_binding_key b_key_orig;
    get_rev_dir_binding_key(&b_key_rev, b_value_rev, &b_key_orig);

    bpf_map_delete_elem(&map_binding, &b_key_orig);
    bpf_map_delete_elem(&map_binding, &b_key_rev);

    bpf_log_debug("no ref, delete binding");

delete_ct:
    bpf_map_delete_elem(&map_ct, key);
#undef BPF_LOG_TOPIC
}

static int ct_timer_cb(void *_map_ct, struct map_ct_key *key,
                       struct map_ct_value *value) {
#define BPF_LOG_TOPIC "ct_timer_cb"
    if (g_deleting_map_entries) {
        // delay the CT deletion till g_deleting_map_entries became false
        bpf_timer_start(&value->timer, 1e9, 0);
        return 0;
    }

    bpf_log_debug("timeout: delete CT %pI4 -> %pI4", &key->external.saddr.ip,
                  &key->external.daddr.ip);

    delete_ct(key);
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct map_ct_value *
insert_new_ct(u8 l4proto, const struct map_ct_key *key,
              const struct map_ct_value *val) {
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
    ret = bpf_timer_start(
        &value->timer,
        l4proto == IPPROTO_TCP ? TIMEOUT_TCP_TRANS : TIMEOUT_PKT_MIN, 0);
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
        l4_check_pseudo = !is_ipv4;
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

    if (is_icmpx_error) {
        if (is_ipv4) {
            ipv4_update_csum_icmp_err(
                skb, l4_off + offsetof(struct icmphdr, checksum),
                icmpx_err_l3_offset(l4_off) + offsetof(struct iphdr, check),
                err_l4_off + l4_to_check_off, from_addr->ip, from_port,
                to_addr->ip, to_port, l4_check_pseudo, l4_check_mangle_0);
        } else {
#ifdef FEAT_IPV6
            ipv6_update_csum_icmp_err(
                skb, l4_off + offsetof(struct icmphdr, checksum),
                err_l4_off + l4_to_check_off, from_addr->ip6, from_port,
                to_addr->ip6, to_port);
#else
            __bpf_unreachable();
#endif
        }
    } else {
        if (is_ipv4) {
            ipv4_update_csum(skb, l4_off + l4_to_check_off, from_addr->ip,
                             from_port, to_addr->ip, to_port, l4_check_pseudo,
                             l4_check_mangle_0);
        } else {
#ifdef FEAT_IPV6
            // For IPv6, checksum pseudo header calculation is required and
            // zero-checksum should not be mangled.
            ipv6_update_csum(skb, l4_off + l4_to_check_off, from_addr->ip6,
                             from_port, to_addr->ip6, to_port);
#else
            __bpf_unreachable();
#endif
        }
    }

    return 0;
}

struct find_port_ctx {
    struct map_binding_key key;
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
    if (!value || value->ref == 0) {
        ctx->found = true;
        return BPF_LOOP_RET_BREAK;
    }

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

static __always_inline void find_port_fallback(struct find_port_ctx *ctx) {
#define BPF_LOG_TOPIC "find_port_fallback"
    // Try random port lookup for 32 times, and the packet would be dropped if
    // no success. However the subsequent packets would still enter this
    // procedure so the port assignment would success eventually, with the cost
    // of previous packets being dropped.
#pragma unroll
    for (int i = 0; i < MAX_PORT_COLLISION_TRIES; i++) {
        ctx->key.from_port = bpf_htons(ctx->curr_port);
        struct map_binding_value *value =
            bpf_map_lookup_elem(&map_binding, &ctx->key);
        if (!value || value->ref == 0) {
            ctx->found = true;
            break;
        }

        ctx->curr_port = (bpf_get_prandom_u32() % ctx->curr_remaining) +
                         ctx->range.begin_port;
    }
#undef BPF_LOG_TOPIC
}

static int __always_inline fill_unique_binding_port(
    struct port_range *proto_range, u8 range_len,
    const struct map_binding_key *key, struct map_binding_value *val) {
#define BPF_LOG_TOPIC "find_binding_port"
    struct find_port_ctx ctx;

    get_rev_dir_binding_key(key, val, &ctx.key);
    ctx.curr_port = bpf_ntohs(ctx.key.from_port);
    ctx.found = false;

    // Annotate as unsigned to avoid signed division on index calculation below
    u32 start_range_idx =
        find_port_range_idx(ctx.curr_port, range_len, proto_range);
    barrier_var(start_range_idx);
    if ((s32)start_range_idx < 0) {
        start_range_idx = bpf_get_prandom_u32() % range_len;
    }

#pragma unroll
    for (int i = 0; i < MAX_PORT_RANGES; i++) {
        if (i >= range_len) {
            break;
        }
        u32 idx = ((start_range_idx + i) % range_len) & MAX_PORT_RANGES_MASK;
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

        if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_loop)) {
            // requires Linux kernel>=5.17
            bpf_loop(65536, find_port_cb, &ctx, 0);
        } else {
            find_port_fallback(&ctx);
        }

        if (ctx.found) {
            val->to_port = ctx.key.from_port;
            bpf_log_debug("found free binding %d -> %d",
                          bpf_ntohs(key->from_port), bpf_ntohs(val->to_port));
            return TC_ACT_OK;
        }
    }

    bpf_log_warn("out of binding port");
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

static __always_inline void
partial_init_binding_value(bool is_ipv4, __be16 to_port,
                           struct map_binding_value *val) {

    val->flags = (is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG);
    val->to_port = to_port;
    val->is_static = false;
    val->use = 0;
    val->ref = 0;
    val->seq = __sync_fetch_and_add(&g_next_binding_seq, 1);
}

static __always_inline int
ingress_lookup_or_new_binding(u32 ifindex, bool is_ipv4,
                              struct external_config *ext_config, u8 l4proto,
                              bool do_new, const struct inet_tuple *reply,
                              struct map_binding_value **b_value_rev_) {
    struct map_binding_key b_key = {
        .ifindex = ifindex,
        .flags = (is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG),
        .l4proto = l4proto,
        .from_port = reply->dport,
        .from_addr = reply->daddr,
    };

    struct map_binding_value *b_value_rev =
        bpf_map_lookup_elem(&map_binding, &b_key);
    if (!b_value_rev) {
        if (!do_new) {
            return TC_ACT_SHOT;
        }
        struct map_binding_value b_value_new;
        partial_init_binding_value(is_ipv4, b_key.from_port, &b_value_new);
        COPY_ADDR6(b_value_new.to_addr.all, b_key.from_addr.all);

        struct port_range *proto_range;
        u8 range_len =
            select_port_range(ext_config, l4proto, RANGE_INBOUND, &proto_range);
        barrier_var(range_len);
        if (range_len == 0) {
            // range_len=0 is defined as the semantic of passthrough NAT for
            // respective IP protocol
            return TC_ACT_UNSPEC;
        }

        int ret = fill_unique_binding_port(proto_range, range_len, &b_key,
                                           &b_value_new);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }

        b_value_rev = insert_new_binding(&b_key, &b_value_new, NULL);
        if (!b_value_rev) {
            barrier();
            return TC_ACT_SHOT;
        }
    }

    *b_value_rev_ = b_value_rev;
    return TC_ACT_OK;
}

int __always_inline egress_fib_lookup_src(struct __sk_buff *skb, bool is_ipv4,
                                          const union u_inet_addr *saddr,
                                          const union u_inet_addr *daddr,
                                          union u_inet_addr *to_addr) {
#define BPF_LOG_TOPIC "egress_fib_lookup_src"
    struct bpf_fib_lookup params = {
        .family = is_ipv4 ? AF_INET : AF_INET6,
        .ifindex = skb->ifindex,
    };

    if (is_ipv4) {
        params.ipv4_src = saddr->ip;
        params.ipv4_dst = daddr->ip;
    } else {
#ifdef FEAT_IPV6
        COPY_ADDR6(params.ipv6_src, saddr->ip6);
        COPY_ADDR6(params.ipv6_dst, daddr->ip6);
#else
        __bpf_unreachable();
#endif
    }
    int ret = bpf_fib_lookup(skb, &params, sizeof(params),
                             BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_SKIP_NEIGH |
                                 BPF_FIB_LOOKUP_SRC);
    if (ret) {
        // The lookup would return -EINVAL if BPF_FIB_LOOKUP_SRC is not
        // supported on current kernel, we then can fallback to use defined
        // external address
        if (ret > 0) {
            bpf_log_error("FIB lookup failed, ret: %d", ret);
        }
        return TC_ACT_SHOT;
    }

    if (is_ipv4) {
        inet_addr_set_ip(to_addr, params.ipv4_src);
    } else {
#ifdef FEAT_IPV6
        inet_addr_set_ip6(to_addr, params.ipv6_src);
#else
        __bpf_unreachable();
#endif
    }

    if (is_ipv4) {
        bpf_log_trace("orig_src:%pI4, orig_dst:%pI4, src:%pI4, dst:%pI4",
                      &saddr->ip, &daddr->ip, &params.ipv4_src,
                      &params.ipv4_dst);
    } else {
#ifdef FEAT_IPV6
        bpf_log_trace("orig_src:%pI6, orig_dst:%pI6, src:%pI6, dst:%pI6",
                      saddr->ip6, daddr->ip6, params.ipv6_src, params.ipv6_dst);
#endif
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
egress_lookup_or_new_binding(struct __sk_buff *skb, bool is_ipv4, u8 l4proto,
                             bool do_new, const struct inet_tuple *origin,
                             struct map_binding_value **b_value_orig_,
                             struct map_binding_value **b_value_rev_) {
#define BPF_LOG_TOPIC "egress_lookup_or_new_binding"
    struct map_binding_key b_key = {
        .ifindex = skb->ifindex,
        .flags =
            BINDING_ORIG_DIR_FLAG | (is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG),
        .l4proto = l4proto,
        .from_port = origin->sport,
        .from_addr = origin->saddr,
    };

    struct map_binding_value *b_value_rev = NULL;
    struct map_binding_value *b_value_orig =
        bpf_map_lookup_elem(&map_binding, &b_key);
    if (!b_value_orig) {
        if (!do_new) {
            return TC_ACT_SHOT;
        }

        // XXX: do NAT64 for origin->daddr if it has NAT64 prefix
        bool nat_x_4 = is_ipv4;
        struct map_binding_value b_value_new;
        partial_init_binding_value(nat_x_4, b_key.from_port, &b_value_new);

        // XXX: use 0 as source address in the case of NAT64
        if (!ENABLE_FIB_LOOKUP_SRC ||
            egress_fib_lookup_src(skb, nat_x_4, &origin->saddr, &origin->daddr,
                                  &b_value_new.to_addr)) {
            if (nat_x_4) {
                inet_addr_set_ip(&b_value_new.to_addr, g_ipv4_external_addr);
            } else {
#ifdef FEAT_IPV6
                inet_addr_set_ip6(&b_value_new.to_addr, g_ipv6_external_addr);
#else
                __bpf_unreachable();
#endif
            }
        }

        int ret;
        struct external_config *ext_config =
            lookup_external_config(nat_x_4, &b_value_new.to_addr);
        if ((ret = nat_check_external_config(ext_config)) != TC_ACT_OK) {
            return ret;
        }

        struct port_range *proto_range;
        u8 range_len = select_port_range(ext_config, l4proto, RANGE_OUTBOUND,
                                         &proto_range);
        barrier_var(range_len);
        if (range_len == 0) {
            // range_len=0 is defined as the semantic of passthrough NAT for
            // respective IP protocol
            return TC_ACT_UNSPEC;
        }

        ret = fill_unique_binding_port(proto_range, range_len, &b_key,
                                       &b_value_new);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }

        b_value_orig = insert_new_binding(&b_key, &b_value_new, &b_value_rev);
        if (!b_value_orig) {
            return TC_ACT_SHOT;
        }
    }

    *b_value_orig_ = b_value_orig;
    *b_value_rev_ = b_value_rev;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

enum {
    LK_CT_ERROR_NEW,
    LK_CT_NONE,
    LK_CT_EXIST,
    LK_CT_NEW,
};

static __always_inline int
ingress_lookup_or_new_ct(u32 ifindex, bool is_ipv4, u8 l4proto, bool do_new,
                         const struct inet_tuple *reply,
                         struct map_binding_value *b_value_rev,
                         struct map_ct_value **ct_value_) {
#define BPF_LOG_TOPIC "ingress_lookup_or_new_ct"
    struct map_ct_key ct_key;
    ct_key.ifindex = ifindex;
    ct_key.flags = is_ipv4 ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG;
    ct_key.l4proto = l4proto;
    ct_key._pad = 0;
    inet_tuple_rev_copy(&ct_key.external, reply);

    struct map_ct_value *ct_value = bpf_map_lookup_elem(&map_ct, &ct_key);
    if (ct_value) {
        if (ct_value->seq == b_value_rev->seq) {
            *ct_value_ = ct_value;
            return LK_CT_EXIST;
        }
        // This CT could become dangling and not refcounted if the binding
        // was deleted in delete_ct() at this point, due to the deleted
        // binding is still available here because of RCU but we might add a
        // new CT referencing the binding(through refcount). Though the CT
        // would fade out eventually due to timeout. Thus we assign a unique
        // sequence number for binding and related CTs to distinguish
        // binding generations. And if the sequence number does not matches
        // between binding and CT, then the CT must be dangling, so we just
        // delete that CT and recreate a CT with new sequence number from
        // binding.
        bpf_map_delete_elem(&map_ct, &ct_key);
        ct_value = NULL;
    }
    if (!ct_value && !do_new) {
        return LK_CT_NONE;
    }

    struct map_binding_key b_key_orig;
    binding_value_to_key(ifindex, BINDING_ORIG_DIR_FLAG, l4proto, b_value_rev,
                         &b_key_orig);
    struct map_binding_value *b_value_orig =
        bpf_map_lookup_elem(&map_binding, &b_key_orig);
    if (!b_value_orig || b_value_orig->seq != b_value_rev->seq) {
        // binding updated, just drop the packet
        return LK_CT_ERROR_NEW;
    }

    // TODO: use initialization helper to set or initialize ever fields
    // manually
    struct map_ct_value ct_value_new;
    ct_value_new.flags =
        FLAGS_IS_IPV4(b_value_rev->flags) ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG;
    ct_value_new.state = CT_INIT_IN;
    COPY_ADDR6(ct_value_new.origin.saddr.all, b_value_rev->to_addr.all);
    ct_value_new.origin.sport = b_value_rev->to_port;
    // XXX: do reverse NAT64 (i.e. append NAT64 prefix) if reply is IPv4 and
    // b_value->flags contains ADDR_IPV6_FLAG
    COPY_ADDR6(ct_value_new.origin.daddr.all, reply->saddr.all);
    ct_value_new.origin.dport =
        is_icmpx(l4proto) ? b_value_rev->to_port : reply->sport;
    ct_value_new.seq = b_value_rev->seq;
    ct_value_new._pad[0] = 0;
    ct_value_new._pad[1] = 0;
    ct_value_new._pad[2] = 0;
    ct_value_new.timer.__opaque[0] = 0;
    ct_value_new.timer.__opaque[1] = 0;

    ct_value = insert_new_ct(l4proto, &ct_key, &ct_value_new);
    if (!ct_value) {
        return LK_CT_ERROR_NEW;
    }

    b_value_orig->ref = BINDING_ORIG_REF_COUNTED;
    __sync_fetch_and_add(&b_value_rev->ref, 1);

    bpf_log_debug("insert new CT");

    *ct_value_ = ct_value;
    return LK_CT_NEW;
#undef BPF_LOG_TOPIC
}

static __always_inline int egress_lookup_or_new_ct(
    u32 ifindex, bool is_ipv4, u8 l4proto, bool do_new,
    const struct inet_tuple *origin, struct map_binding_value *b_value_orig,
    struct map_binding_value *b_value_rev, struct map_ct_value **ct_value_) {
#define BPF_LOG_TOPIC "egress_lookup_or_new_ct"
    struct map_ct_key ct_key;
    ct_key.ifindex = ifindex;
    ct_key.flags =
        FLAGS_IS_IPV4(b_value_orig->flags) ? ADDR_IPV4_FLAG : ADDR_IPV6_FLAG;
    ct_key.l4proto = l4proto;
    ct_key._pad = 0;
    COPY_ADDR6(ct_key.external.saddr.all, b_value_orig->to_addr.all);
    ct_key.external.sport = b_value_orig->to_port;
    // XXX: do NAT64 if origin is IPv6 and b_value->flags contains
    // ADDR_IPV4_FLAG
    COPY_ADDR6(ct_key.external.daddr.all, origin->daddr.all);
    ct_key.external.dport =
        is_icmpx(l4proto) ? b_value_orig->to_port : origin->dport;

    struct map_ct_value *ct_value = bpf_map_lookup_elem(&map_ct, &ct_key);
    if (ct_value) {
        if (ct_value->seq == b_value_orig->seq) {
            *ct_value_ = ct_value;
            return LK_CT_EXIST;
        }
        bpf_map_delete_elem(&map_ct, &ct_key);
        ct_value = NULL;
    }
    if (!ct_value && !do_new) {
        return LK_CT_NONE;
    }

    if (!b_value_rev) {
        struct map_binding_key b_key_rev;
        binding_value_to_key(ifindex, 0, l4proto, b_value_orig, &b_key_rev);
        b_value_rev = bpf_map_lookup_elem(&map_binding, &b_key_rev);
        if (!b_value_rev) {
            return LK_CT_ERROR_NEW;
        }
    }
    if (b_value_rev->seq != b_value_orig->seq) {
        // binding updated, just drop the packet
        return LK_CT_ERROR_NEW;
    }

    struct map_ct_value ct_value_new = {.flags = is_ipv4 ? ADDR_IPV4_FLAG
                                                         : ADDR_IPV6_FLAG,
                                        .origin = *origin,
                                        .state = CT_INIT_OUT,
                                        .seq = b_value_rev->seq};
    ct_value = insert_new_ct(l4proto, &ct_key, &ct_value_new);
    if (!ct_value) {
        return LK_CT_ERROR_NEW;
    }

    __sync_fetch_and_add(&b_value_rev->ref, 1);
    __sync_fetch_and_add(&b_value_rev->use, 1);
    b_value_orig->ref = BINDING_ORIG_REF_COUNTED;

    bpf_log_debug("insert new CT");

    *ct_value_ = ct_value;
    return LK_CT_NEW;
#undef BPF_LOG_TOPIC
}

static __always_inline bool ct_change_state(struct map_ct_value *ct_value,
                                            u32 curr_state, u32 next_state) {
    return __sync_bool_compare_and_swap(&ct_value->state, curr_state,
                                        next_state);
}

static __always_inline int ct_reset_timer(struct map_ct_value *ct_value,
                                          u64 timeout) {
    return bpf_timer_start(&ct_value->timer, timeout, 0);
}

static __always_inline int
ct_state_transition(u32 ifindex, u8 l4proto, u8 pkt_type, bool is_outbound,
                    struct map_binding_value *b_value,
                    struct map_ct_value *ct_value) {
#define BPF_LOG_TOPIC "ct_state_transition"
    u32 curr_state = ct_value->state;

#define NEW_STATE(__state)                                                     \
    if (!ct_change_state(ct_value, curr_state, (__state))) {                   \
        return TC_ACT_SHOT;                                                    \
    }
#define RESET_TIMER(__timeout) ct_reset_timer(ct_value, (__timeout))

    switch (curr_state) {
    case CT_INIT_IN:
        if (is_outbound) {
            if (pkt_type != PKT_CONNLESS && pkt_type != PKT_TCP_SYN) {
                break;
            }

            struct map_binding_key b_key_rev;
            binding_value_to_key(ifindex, 0, l4proto, b_value, &b_key_rev);
            struct map_binding_value *b_value_rev =
                bpf_map_lookup_elem(&map_binding, &b_key_rev);
            if (!b_value_rev) {
                return TC_ACT_SHOT;
            }
            if (b_value_rev->seq != ct_value->seq) {
                // the CT is obsolete, schedule the deletion
                RESET_TIMER(0);
                return TC_ACT_SHOT;
            }

            NEW_STATE(CT_ESTABLISHED);
            __sync_fetch_and_add(&b_value_rev->use, 1);
            RESET_TIMER(pkt_type == PKT_CONNLESS ? TIMEOUT_PKT_DEFAULT
                                                 : TIMEOUT_TCP_TRANS);
            bpf_log_debug("INIT_IN -> ESTABLISHED");
        } else if (b_value->use != 0) {
            // XXX: or just don't refresh timer and wait recreating CT instead
            RESET_TIMER(pkt_type == PKT_CONNLESS ? TIMEOUT_PKT_MIN
                                                 : TIMEOUT_TCP_TRANS);
            bpf_log_trace("INIT_IN refresh timer");
        }
        break;
    case CT_INIT_OUT:
        if (pkt_type != PKT_CONNLESS && pkt_type != PKT_TCP_SYN) {
            break;
        }
        if (is_outbound) {
            RESET_TIMER(pkt_type == PKT_CONNLESS ? TIMEOUT_PKT_MIN
                                                 : TIMEOUT_TCP_TRANS);
        } else {
            NEW_STATE(CT_ESTABLISHED);
            RESET_TIMER(pkt_type == PKT_CONNLESS ? TIMEOUT_PKT_DEFAULT
                                                 : TIMEOUT_TCP_EST);
            bpf_log_debug("INIT_OUT -> ESTABLISHED");
        }
        break;
    case CT_ESTABLISHED:
        if (pkt_type == PKT_CONNLESS) {
            if (is_outbound) {
                RESET_TIMER(TIMEOUT_TCP_EST);
            }
        } else if (pkt_type == PKT_TCP_DATA) {
            // XXX: should we allow refreshing from inbound?
            RESET_TIMER(TIMEOUT_TCP_EST);
        } else if (pkt_type == PKT_TCP_FIN) {
            NEW_STATE(is_outbound ? CT_FIN_OUT : CT_FIN_IN);
            bpf_log_debug("ESTABLISHED -> FIN_IN/FIN_OUT");
        } else if (pkt_type == PKT_TCP_RST) {
            NEW_STATE(CT_TRANS);
            RESET_TIMER(TIMEOUT_TCP_TRANS);
            bpf_log_debug("ESTABLISHED -> TRANS");
        }
        break;
    case CT_TRANS:
        if (pkt_type != PKT_TCP_RST) {
            NEW_STATE(CT_ESTABLISHED);
            RESET_TIMER(TIMEOUT_TCP_EST);
            bpf_log_debug("TRANS -> ESTABLISHED");
        }
        break;
    case CT_FIN_IN:
        if (pkt_type == PKT_TCP_FIN) {
            if (is_outbound) {
                NEW_STATE(CT_FIN_IN_OUT);
                RESET_TIMER(TIMEOUT_TCP_TRANS);
                bpf_log_debug("FIN_IN -> FIN_IN_OUT");
            }
        } else {
            RESET_TIMER(TIMEOUT_TCP_EST);
        }
        break;
    case CT_FIN_OUT:
        if (pkt_type == PKT_TCP_FIN) {
            if (!is_outbound) {
                NEW_STATE(CT_FIN_IN_OUT);
                RESET_TIMER(TIMEOUT_TCP_TRANS);
                bpf_log_debug("FIN_OUT -> FIN_IN_OUT");
            }
        } else {
            RESET_TIMER(TIMEOUT_TCP_EST);
        }
        break;
    case CT_FIN_IN_OUT:
        break;
    default:
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int get_is_ipv4(struct __sk_buff *skb, bool *is_ipv4_) {
    bool is_ipv4;
    if (HAS_ETH_ENCAP) {
        struct ethhdr *eth;
        if (VALIDATE_PULL(skb, &eth, 0, sizeof(*eth))) {
            return TC_ACT_SHOT;
        }

        if (eth->h_proto == bpf_htons(ETH_P_IP)) {
            is_ipv4 = true;
#ifdef FEAT_IPV6
        } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
            is_ipv4 = false;
#endif
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 *p_version;
        if (VALIDATE_PULL(skb, &p_version, 0, sizeof(*p_version))) {
            return TC_ACT_SHOT;
        }

        u8 version = (*p_version) >> 4;
        if (version == 4) {
            is_ipv4 = true;
#ifdef FEAT_IPV6
        } else if (version == 6) {
            is_ipv4 = false;
#endif
        } else {
            return TC_ACT_UNSPEC;
        }
    }
    *is_ipv4_ = is_ipv4;
    return TC_ACT_OK;
}

// Ensure we are using PKT_IS_IPV4()
#undef IS_IPV4
#ifdef FEAT_IPV6
#define PKT_IS_IPV4() (is_ipv4)
#else
#define PKT_IS_IPV4() (true)
#endif

SEC("classifier")
int ingress_rev_snat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "ingress<=="
    int ret;
    // XXX: separate out IPV4 and IPV6 outer branches and dispatch with tail
    // call to further reduce complexity
    // Also somehow use a separate is_ipv4 variable reduce complexity greatly..
    bool is_ipv4;
    ret = get_is_ipv4(skb, &is_ipv4);
    if (ret != TC_ACT_OK) {
        return ret;
    }

#ifdef FEAT_IPV6
    barrier_var(is_ipv4);
    if ((is_ipv4 && !INGRESS_IPV4) || (!is_ipv4 && !INGRESS_IPV6)) {
        return TC_ACT_UNSPEC;
    }
#else
    if (!INGRESS_IPV4) {
        return TC_ACT_UNSPEC;
    }
#endif

    // XXX: just use local variables instead
    struct packet_info pkt;
    ret = parse_packet(skb, PKT_IS_IPV4(), TC_SKB_L3_OFF(), &pkt);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    struct external_config *ext_config =
        lookup_external_config(PKT_IS_IPV4(), &pkt.tuple.daddr);
    if ((ret = nat_check_external_config(ext_config)) != TC_ACT_OK) {
        return ret;
    }

    if ((ret = fragment_track(skb, &pkt, 0)) != TC_ACT_OK) {
        return ret;
    }

    if (!nat_in_binding_range(ext_config, pkt.nexthdr,
                              bpf_ntohs(pkt.tuple.dport))) {
        return TC_ACT_UNSPEC;
    }

    bool is_icmpx_error = is_icmpx_error_pkt(&pkt);
    bool do_inbound_binding = ALLOW_INBOUND_ICMPX && !g_deleting_map_entries &&
                              !is_icmpx_error && is_icmpx(pkt.nexthdr);

    struct map_binding_value *b_value_rev;
    ret = ingress_lookup_or_new_binding(skb->ifindex, PKT_IS_IPV4(), ext_config,
                                        pkt.nexthdr, do_inbound_binding,
                                        &pkt.tuple, &b_value_rev);
    if (ret == TC_ACT_UNSPEC) {
        return TC_ACT_UNSPEC;
    } else if (ret != TC_ACT_OK) {
        // XXX: no free port, send back ICMP network unreachable
        return TC_ACT_SHOT;
    }

    if (!b_value_rev->is_static) {
        bool do_inbound_ct =
            !g_deleting_map_entries && !is_icmpx_error &&
            ((b_value_rev->use != 0 && pkt_allow_initiating_ct(pkt.pkt_type)) ||
             (do_inbound_binding &&
              inet_addr_equal(&b_value_rev->to_addr, &pkt.tuple.daddr)));

        struct map_ct_value *ct_value;
        ret = ingress_lookup_or_new_ct(skb->ifindex, PKT_IS_IPV4(), pkt.nexthdr,
                                       do_inbound_ct, &pkt.tuple, b_value_rev,
                                       &ct_value);
        if (ret == LK_CT_NONE || ret == LK_CT_ERROR_NEW) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error && ret == LK_CT_EXIST) {
            ct_state_transition(skb->ifindex, pkt.nexthdr, pkt.pkt_type, false,
                                b_value_rev, ct_value);
        }
    }

    // modify dest
    ret = modify_headers(skb, PKT_IS_IPV4(), is_icmpx_error, pkt.nexthdr,
                         TC_SKB_L3_OFF(), pkt.l4_off, pkt.err_l4_off, false,
                         &pkt.tuple.daddr, pkt.tuple.dport,
                         &b_value_rev->to_addr, b_value_rev->to_port);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("classifier")
int egress_snat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "egress ==>"
    int ret;
    bool is_ipv4;
    ret = get_is_ipv4(skb, &is_ipv4);
    if (ret != TC_ACT_OK) {
        return ret;
    }

#ifdef FEAT_IPV6
    barrier_var(is_ipv4);
    if ((is_ipv4 && !EGRESS_IPV4) || (!is_ipv4 && !EGRESS_IPV6)) {
        return TC_ACT_UNSPEC;
    }
#else
    if (!EGRESS_IPV4) {
        return TC_ACT_UNSPEC;
    }
#endif

    // XXX: just use local variables instead
    struct packet_info pkt;
    ret = parse_packet(skb, PKT_IS_IPV4(), TC_SKB_L3_OFF(), &pkt);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    bool do_hairpin = false;
    bool pass_nat = false;
    struct dest_config *dest_config =
        lookup_dest_config(PKT_IS_IPV4(), &pkt.tuple.daddr);
    if (dest_config) {
        do_hairpin = dest_hairpin(dest_config);
        pass_nat = dest_pass_nat(dest_config);
    }

    struct external_config *ext_config =
        lookup_external_config(PKT_IS_IPV4(), &pkt.tuple.saddr);
    if (ext_config) { // this packet was send from local NAT host
        if (external_pass_nat(ext_config)) {
            goto check_hairpin;
        }
    } else if (pass_nat) {
        goto check_hairpin;
    }

    if ((ret = fragment_track(skb, &pkt, FRAG_TRACK_EGRESS_FLAG)) !=
        TC_ACT_OK) {
        if (ret == TC_ACT_UNSPEC) {
            goto check_hairpin;
        }
        return TC_ACT_SHOT;
    }

    if (ext_config && !is_internal(ext_config)) {
        if (!nat_in_binding_range(ext_config, pkt.nexthdr,
                                  bpf_ntohs(pkt.tuple.sport))) {
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
    bool do_new = !g_deleting_map_entries && !is_icmpx_error &&
                  pkt_allow_initiating_ct(pkt.pkt_type);

    struct map_binding_value *b_value_orig, *b_value_rev;
    ret = egress_lookup_or_new_binding(skb, PKT_IS_IPV4(), pkt.nexthdr, do_new,
                                       &pkt.tuple, &b_value_orig, &b_value_rev);
    if (ret == TC_ACT_UNSPEC) {
        goto check_hairpin;
    } else if (ret != TC_ACT_OK) {
        // XXX: no free port, send back ICMP network unreachable
        return TC_ACT_SHOT;
    }

    if (!b_value_orig->is_static) {
        struct map_ct_value *ct_value;
        ret = egress_lookup_or_new_ct(skb->ifindex, PKT_IS_IPV4(), pkt.nexthdr,
                                      do_new, &pkt.tuple, b_value_orig,
                                      b_value_rev, &ct_value);
        if (ret == LK_CT_NONE || ret == LK_CT_ERROR_NEW) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error && ret == LK_CT_EXIST) {
            ct_state_transition(skb->ifindex, pkt.nexthdr, pkt.pkt_type, true,
                                b_value_orig, ct_value);
        }
    }

    // modify source
    ret = modify_headers(skb, PKT_IS_IPV4(), is_icmpx_error, pkt.nexthdr,
                         TC_SKB_L3_OFF(), pkt.l4_off, pkt.err_l4_off, true,
                         &pkt.tuple.saddr, pkt.tuple.sport,
                         &b_value_orig->to_addr, b_value_orig->to_port);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

check_hairpin:
    if (!do_hairpin) {
        return TC_ACT_UNSPEC;
    }

    if (HAS_ETH_ENCAP) {
        void *data_end = ctx_data_end(skb);
        struct ethhdr *eth = ctx_data(skb);
        if ((void *)(eth + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        // somehow printk MAC format token "%pM" does not work in BPF
        bpf_log_trace("hairpin smac: %x:%x:%x:%x:%x:%x", eth->h_source[0],
                      eth->h_source[1], eth->h_source[2], eth->h_source[3],
                      eth->h_source[4], eth->h_source[5]);
        bpf_log_trace("hairpin dmac: %x:%x:%x:%x:%x:%x", eth->h_dest[0],
                      eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
                      eth->h_dest[4], eth->h_dest[5]);

        u8 smac[6];
        __builtin_memcpy(smac, eth->h_source, sizeof(smac));
        __builtin_memcpy(eth->h_source, eth->h_dest, sizeof(smac));
        __builtin_memcpy(eth->h_dest, smac, sizeof(smac));
    } else {
        bpf_log_trace("IP hairpin");
    }

    return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
#undef BPF_LOG_TOPIC
}

char _license[] SEC("license") = "GPL";
