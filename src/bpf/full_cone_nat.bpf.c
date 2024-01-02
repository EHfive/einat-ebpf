// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#include "full_cone_nat.h"

#define DEFAULT_MAX_ENTRIES (65536 * 4)

const volatile u8 nat_filtering_mode = NAT_FILTERING_INDEPENDENT;
const volatile u32 ct_mark = 0;

u32 mapping_lock SEC(".data") = 0;
bool pausing SEC(".data") = false;


u8 log_level SEC(".data") = BPF_LOG_LEVEL_DEBUG;
#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL log_level

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mapping_key);
    __type(value, struct mapping_value);
    // upper bound: <number of interfaces attached> * <number of ip addresses> *
    // 65536
    __uint(max_entries, DEFAULT_MAX_ENTRIES);
} mapping_table SEC(".maps");

// connection set to check if an origin was added to a mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_key);
    __type(value, struct conn_value);
    __uint(max_entries, DEFAULT_MAX_ENTRIES);
} conn_table SEC(".maps");

#ifdef FEATURE_BPF_ATOMIC

static inline __attribute__((always_inline)) bool spin_lock_acquire() {
#define BPF_LOG_TOPIC "lock"
    if (!__atomic_exchange_n(&mapping_lock, 1, __ATOMIC_ACQUIRE)) {
        return true;
    }
    bpf_log_trace("someone else is holding the lock");

    bpf_repeat(BPF_MAX_LOOPS) {
        if (!__atomic_exchange_n(&mapping_lock, 1, __ATOMIC_ACQUIRE)) {
            return true;
        }
    }
    bpf_log_error("failed to acquire lock");
    return false;
#undef BPF_LOG_TOPIC
}

static inline __attribute__((always_inline)) void spin_lock_release() {
    // Somehow __ATOMIC_RELEASE fails to compile
    __atomic_exchange_n(&mapping_lock, 0, __ATOMIC_ACQ_REL);
}

#else
static inline __attribute__((always_inline)) bool spin_lock_acquire() {
    return true;
}
static inline __attribute__((always_inline)) void spin_lock_release() {}
#endif

static inline __attribute__((always_inline)) int
get_tuple(const struct __sk_buff *skb, bool reverse,
          struct bpf_sock_tuple *p_tuple, bool *p_is_ipv4, u8 *p_l4_proto) {
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)(void *)(long)skb->data;

    void *trans_data;
    __be16 src_port = 0;
    __be16 dst_port = 0;
    bool is_ipv4;
    u8 l4_proto;

    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)((void *)eth + sizeof(*eth));
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        if (reverse) {
            p_tuple->ipv4.saddr = iph->daddr;
            p_tuple->ipv4.daddr = iph->saddr;
        } else {
            p_tuple->ipv4.saddr = iph->saddr;
            p_tuple->ipv4.daddr = iph->daddr;
        }
        is_ipv4 = true;
        l4_proto = iph->protocol;
        trans_data = (void *)iph + (iph->ihl * 4);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)((void *)eth + sizeof(*eth));
        if ((void *)(ip6h + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        if (reverse) {
            COPY_ADDR6(p_tuple->ipv6.saddr, ip6h->daddr.in6_u.u6_addr32);
            COPY_ADDR6(p_tuple->ipv6.daddr, ip6h->saddr.in6_u.u6_addr32);
        } else {
            COPY_ADDR6(p_tuple->ipv6.saddr, ip6h->saddr.in6_u.u6_addr32);
            COPY_ADDR6(p_tuple->ipv6.daddr, ip6h->daddr.in6_u.u6_addr32);
        }
        is_ipv4 = false;
        l4_proto = ip6h->nexthdr;
        trans_data = ip6h + 1;
    } else {
        return TC_ACT_UNSPEC;
    }

    *p_is_ipv4 = is_ipv4;
    *p_l4_proto = l4_proto;

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)trans_data;
        if ((void *)(tcph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        if (reverse) {
            src_port = tcph->dest;
            dst_port = tcph->source;
        } else {
            src_port = tcph->source;
            dst_port = tcph->dest;
        }
    } else if (l4_proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)trans_data;
        if ((void *)(udph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        if (reverse) {
            src_port = udph->dest;
            dst_port = udph->source;
        } else {
            src_port = udph->source;
            dst_port = udph->dest;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    if (is_ipv4) {
        p_tuple->ipv4.sport = src_port;
        p_tuple->ipv4.dport = dst_port;
    } else {
        p_tuple->ipv6.sport = src_port;
        p_tuple->ipv6.dport = dst_port;
    }

    return TC_ACT_OK;
}

static inline __attribute__((always_inline)) bool
check_mapping_active(struct __sk_buff *skb, const struct mapping_key *m_key,
                     struct mapping_value *m, bool is_ipv4, u8 l4proto) {
#define BPF_LOG_TOPIC "check_mapping"
    int ret;
    bpf_spin_lock(&m->lock);
    int len = m->len;
    bpf_spin_unlock(&m->lock);

    int i = 0;
    bpf_for(i, 0, len) {
        bpf_log_trace("looping %d", i);
        struct mapping_origin *origin;
        struct bpf_list_node *n;
        struct bpf_sock_tuple bpf_tuple;
        struct bpf_ct_opts ct_opts = {.netns_id = -1, .l4proto = l4proto};

        bpf_spin_lock(&m->lock);
        n = bpf_list_pop_front(&m->origin_list_head);
        if (n)
            m->len--;
        bpf_spin_unlock(&m->lock);
        if (!n) {
            bpf_log_error("racing, origin list length not sync");
            return false;
        }

        origin = container_of(n, typeof(*origin), node);

        bpf_sock_tuple_parse(&bpf_tuple, is_ipv4, &origin->orig_tuple);
        struct nf_conn *ct = bpf_skb_ct_lookup(skb, &bpf_tuple,
                                               is_ipv4 ? sizeof(bpf_tuple.ipv4)
                                                       : sizeof(bpf_tuple.ipv6),
                                               &ct_opts, NF_BPF_CT_OPTS_SZ);
        bool active = ct && ct_opts.dir == IP_CT_DIR_ORIGINAL &&
                      (ct->status & IPS_DYING) != IPS_DYING;
        if (ct) {
            bpf_ct_release(ct);
        }
        if (!active) {
            struct conn_key c_key = {0};
            conn_key_parse(&c_key, m_key, &origin->orig_tuple);

            bpf_log_debug("clean expired mapping");
            if ((ret = bpf_map_delete_elem(&conn_table, &c_key))) {
                bpf_log_error("delete conn failed, err:%d", ret);
            }

            bpf_obj_drop(origin);
            continue;
        }

        bpf_spin_lock(&m->lock);
        if ((ret = bpf_list_push_back(&m->origin_list_head, &origin->node))) {
            bpf_spin_unlock(&m->lock);
            bpf_log_error("push back origin failed, err: %d", ret);
        } else {
            m->len++;
            bpf_spin_unlock(&m->lock);
        }

        if (active) {
            return true;
        }
    }

    return false;
#undef BPF_LOG_TOPIC
}

static inline __attribute__((always_inline)) bool
delete_mapping(const struct mapping_key *m_key, struct mapping_value *m) {
#define BPF_LOG_TOPIC "delete_mapping"
    int ret;
    bpf_spin_lock(&m->lock);
    int len = m->len;
    bpf_spin_unlock(&m->lock);

    int i = 0;
    bpf_for(i, 0, len) {
        bpf_log_trace("looping %d", i);
        struct mapping_origin *origin;
        struct bpf_list_node *n;

        bpf_spin_lock(&m->lock);
        n = bpf_list_pop_front(&m->origin_list_head);
        if (n)
            m->len--;
        bpf_spin_unlock(&m->lock);
        if (!n) {
            bpf_log_error("racing, origin list length not sync");
            break;
        }
        origin = container_of(n, typeof(*origin), node);

        struct conn_key c_key = {0};
        conn_key_parse(&c_key, m_key, &origin->orig_tuple);

        bpf_log_debug(
            "delete conn mapping ext:%x:%d %x:%d %x:%d -> %x:%d",
            bpf_ntohl(c_key.key.ext_addr.ip), bpf_ntohs(c_key.key.ext_port),
            bpf_ntohl(c_key.origin.saddr.ip), bpf_ntohs(c_key.origin.sport),
            bpf_ntohl(c_key.origin.daddr.ip), bpf_ntohs(c_key.origin.dport));
        if ((ret = bpf_map_delete_elem(&conn_table, &c_key))) {
            bpf_log_error("delete conn failed, err: %d", ret);
        }

        bpf_obj_drop(origin);
    }

    return bpf_map_delete_elem(&mapping_table, m_key) == 0;
#undef BPF_LOG_TOPIC
}

static inline __attribute__((always_inline)) bool
push_mapping_origin(const struct mapping_key *m_key, struct mapping_value *m,
                    struct inet_tuple *orig_tuple, bool update) {
#define BPF_LOG_TOPIC "push_origin"

    int ret;
    struct conn_key c_key = {0};

    conn_key_parse(&c_key, m_key, orig_tuple);

    bpf_log_debug(
        "inserting conn mapping ext:%x:%d %x:%d -> %x:%d %d",
        bpf_ntohl(c_key.key.ext_addr.ip), bpf_ntohs(c_key.key.ext_port),
        bpf_ntohl(c_key.origin.saddr.ip), bpf_ntohs(c_key.origin.sport),
        bpf_ntohl(c_key.origin.daddr.ip), bpf_ntohs(c_key.origin.dport));

    struct conn_value *c = bpf_map_lookup_elem(&conn_table, &c_key);
    if (c) {
        if (!update) {
            bpf_log_error("origin already added, racing");
        } else {
            bpf_log_debug("origin already added, success");
        }
        return update;
    }

    struct conn_value c_new = {0};
    struct mapping_origin *origin = bpf_obj_new(typeof(*origin));
    if (!origin) {
        return false;
    }
    inet_tuple_copy(&origin->orig_tuple, orig_tuple);

    bpf_spin_lock(&m->lock);
    if ((ret = bpf_list_push_back(&m->origin_list_head, &origin->node))) {
        bpf_spin_unlock(&m->lock);
        bpf_log_error("push back origin failed, err: %d", ret);
        return false;
    } else {
        m->len++;
    }
    bpf_spin_unlock(&m->lock);

    if ((ret = bpf_map_update_elem(&conn_table, &c_key, &c_new, BPF_NOEXIST))) {
        bpf_log_error("conn item insertion full or racing, err: %d", ret);
        return false;
    }

    return true;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int ingress_add_ct(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "ingress"

    struct bpf_sock_tuple bpf_tuple = {0};
    bool is_ipv4;
    u8 l4proto;

    if (pausing) {
        return TC_ACT_UNSPEC;
    }

    int ret = get_tuple(skb, false, &bpf_tuple, &is_ipv4, &l4proto);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }
    if (l4proto != IPPROTO_UDP) {
        return TC_ACT_UNSPEC;
    }

    struct bpf_ct_opts ct_opts = {.netns_id = -1, .l4proto = l4proto};
    struct nf_conn *ct = bpf_skb_ct_lookup(skb, &bpf_tuple,
                                           is_ipv4 ? sizeof(bpf_tuple.ipv4)
                                                   : sizeof(bpf_tuple.ipv6),
                                           &ct_opts, NF_BPF_CT_OPTS_SZ);
    if (ct) {
        bpf_ct_release(ct);
        return TC_ACT_UNSPEC;
    }

    struct mapping_key key = {
        .ifindex = skb->ifindex,
        .is_ipv4 = is_ipv4,
        .ext_addr.all = {0},
        .dest_addr.all = {0},
    };
    if (is_ipv4) {
        key.ext_addr.ip = bpf_tuple.ipv4.daddr;
        key.ext_port = bpf_tuple.ipv4.dport;
    } else {
        COPY_ADDR6(key.ext_addr.ip6, bpf_tuple.ipv6.daddr);
        key.ext_port = bpf_tuple.ipv6.dport;
    }
    if (nat_filtering_mode == NAT_FILTERING_DEST_ADDRESS) {
        if (is_ipv4) {
            key.dest_addr.ip = bpf_tuple.ipv4.saddr;
        } else {
            COPY_ADDR6(key.dest_addr.ip6, bpf_tuple.ipv6.saddr);
        }
    }

    if (!spin_lock_acquire()) {
        return TC_ACT_UNSPEC;
    }

    struct mapping_value *m = bpf_map_lookup_elem(&mapping_table, &key);
    if (!m) {
        // SNAT has not seen from egress, bail out
        goto lk_done;
    }

    bpf_log_debug("ingress no ct, is_ipv4:%d", is_ipv4);
    if (!check_mapping_active(skb, &key, m, is_ipv4, l4proto)) {
        bpf_log_debug("mapping not active");
        if (!delete_mapping(&key, m)) {
            bpf_log_error("delete mapping failed");
        }
        goto lk_done;
    }

    bpf_log_debug("ingress found match");

    struct bpf_sock_tuple intern_tuple;
    if (is_ipv4) {
        // internal source address & port
        intern_tuple.ipv4.saddr = m->orig_addr.ip;
        intern_tuple.ipv4.sport = m->orig_port;
        // destination address & port from internal perspective
        intern_tuple.ipv4.daddr = bpf_tuple.ipv4.saddr;
        intern_tuple.ipv4.dport = bpf_tuple.ipv4.sport;
    } else {
        COPY_ADDR6(intern_tuple.ipv6.saddr, m->orig_addr.ip6);
        intern_tuple.ipv6.sport = m->orig_port;
        COPY_ADDR6(intern_tuple.ipv6.daddr, bpf_tuple.ipv6.saddr);
        intern_tuple.ipv6.dport = bpf_tuple.ipv6.sport;
    }

    struct bpf_ct_opts ct_opts_2 = {.netns_id = -1, .l4proto = l4proto};

    struct nf_conn___init *cf_conn_init = bpf_skb_ct_alloc(
        skb, &intern_tuple,
        is_ipv4 ? sizeof(intern_tuple.ipv4) : sizeof(intern_tuple.ipv6),
        &ct_opts_2, NF_BPF_CT_OPTS_SZ);
    if (!cf_conn_init) {
        goto lk_done;
    }

    if (bpf_core_field_exists(cf_conn_init->ct.mark)) {
        cf_conn_init->ct.mark = ct_mark;
    }

    union nf_inet_addr ext_addr = {0};
    if (is_ipv4) {
        ext_addr.ip = bpf_tuple.ipv4.daddr;
    } else {
        COPY_ADDR6(ext_addr.ip6, bpf_tuple.ipv6.daddr);
    }

    // Fake a internal initialed SNAT connection with the same source mapping we
    // collected at egress.
    // We do SNAT instead of DNAT here because nf_nat module
    // would reuse active source mapping(including the one we added here)
    // for new SNATs (search "nat_bysource" in kernel source). However, If we
    // use DNAT, the same SNAT source mapping would not be guaranteed for new
    // connections originated from internal if the original SNAT conntrack seen
    // from egress expires, as there is no other conntrack that share the same
    // source mapping keeps the mapping alive.
    bpf_ct_set_nat_info(cf_conn_init, &ext_addr, bpf_ntohs(key.ext_port),
                        NF_NAT_MANIP_SRC);
    bpf_ct_set_timeout(cf_conn_init, 30000);

    struct nf_conn *nf_conn = bpf_ct_insert_entry(cf_conn_init);
    if (!nf_conn) {
        goto lk_done;
    }
    bpf_ct_change_status(nf_conn, IPS_SEEN_REPLY);

    struct inet_tuple orig_tuple = {0};
    inet_tuple_parse_nf(&orig_tuple,
                        &nf_conn->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    bpf_ct_release(nf_conn);

    if (!push_mapping_origin(&key, m, &orig_tuple, true)) {
        goto lk_done;
    }

    if (is_ipv4)
        bpf_log_info("ingress mapping added %x:%d len:%d",
                     bpf_ntohl(m->orig_addr.ip), bpf_ntohs(m->orig_port),
                     m->len);

lk_done:
    spin_lock_release();
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int egress_collect_snat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "egress"

    int ret;
    struct bpf_sock_tuple bpf_tuple = {0};
    bool is_ipv4;
    u8 l4proto;

    if (pausing) {
        return TC_ACT_UNSPEC;
    }

    // build tuple for reply direction
    ret = get_tuple(skb, true, &bpf_tuple, &is_ipv4, &l4proto);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }
    if (l4proto != IPPROTO_UDP) {
        return TC_ACT_UNSPEC;
    }

    struct bpf_ct_opts ct_opts = {.netns_id = -1, .l4proto = l4proto};
    struct nf_conn *ct = bpf_skb_ct_lookup(skb, &bpf_tuple,
                                           is_ipv4 ? sizeof(bpf_tuple.ipv4)
                                                   : sizeof(bpf_tuple.ipv6),
                                           &ct_opts, NF_BPF_CT_OPTS_SZ);
    if (!ct) {
        return TC_ACT_UNSPEC;
    }

    struct nf_conntrack_tuple *tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
    struct inet_tuple orig_tuple = {0};
    inet_tuple_parse_nf(&orig_tuple, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);

    // On egress side we only care connections initiated from internal
    if (ct_opts.dir != IP_CT_DIR_REPLY) {
        goto ct_done;
    }
    if ((ct->status & (IPS_SRC_NAT | IPS_DYING)) != IPS_SRC_NAT) {
        goto ct_done;
    }

    struct mapping_key key = {
        .ifindex = skb->ifindex,
        .is_ipv4 = is_ipv4,
        .ext_port = tuple->dst.u.all,
        .ext_addr.all = {0},
        .dest_addr.all = {0},
    };
    COPY_ADDR6(key.ext_addr.all, tuple->dst.u3.all);
    if (nat_filtering_mode == NAT_FILTERING_DEST_ADDRESS) {
        COPY_ADDR6(key.dest_addr.all, tuple->src.u3.all);
    }

    if (is_ipv4) {
        bpf_log_debug(
            "SNAT found, ct status:%x origin: %x:%d -> %x:%d reply: %x:%d <- "
            "%x:%d %d->%d",
            ct->status, bpf_ntohl(orig_tuple.saddr.ip),
            bpf_ntohs(orig_tuple.sport), bpf_ntohl(orig_tuple.daddr.ip),
            bpf_ntohs(orig_tuple.dport), bpf_ntohl(tuple->src.u3.ip),
            bpf_ntohs(tuple->src.u.all), bpf_ntohl(tuple->dst.u3.ip),
            bpf_ntohs(tuple->dst.u.all), skb->ingress_ifindex, skb->ifindex);
    }

    bpf_ct_release(ct);

    if (!spin_lock_acquire()) {
        return TC_ACT_UNSPEC;
    }

    bool add_new_mapping = true;
    struct mapping_value *m = bpf_map_lookup_elem(&mapping_table, &key);
    if (m) {
        bpf_log_debug("found old mapping");
        add_new_mapping =
            !(m->orig_port == orig_tuple.sport &&
              __builtin_memcmp(m->orig_addr.all, orig_tuple.saddr.all,
                               sizeof(m->orig_addr.all)) == 0);
        if (add_new_mapping) {
            // TODO reuse old mapping
            if (!delete_mapping(&key, m)) {
                bpf_log_error("delete old mapping failed");
                goto lk_done;
            }
        } else if (!push_mapping_origin(&key, m, &orig_tuple, true)) {
            goto lk_done;
        }
    }

    if (add_new_mapping) {
        bpf_log_info("add new mapping");
        struct mapping_value m_new = {
            .orig_addr.all = {0},
            .orig_port = orig_tuple.sport,
            .len = 0,
        };
        COPY_ADDR6(m_new.orig_addr.all, orig_tuple.saddr.all);

        if ((ret = bpf_map_update_elem(&mapping_table, &key, &m_new,
                                       BPF_NOEXIST))) {
            bpf_log_error("mapping item insertion full or racing, err: %d",
                          ret);
            goto lk_done;
        }
        m = bpf_map_lookup_elem(&mapping_table, &key);
        if (!m) {
            bpf_log_error("racing, item got removed");
            goto lk_done;
        }

        if (!push_mapping_origin(&key, m, &orig_tuple, false)) {
            goto lk_done;
        }
    }

lk_done:
    spin_lock_release();
    return TC_ACT_UNSPEC;
ct_done:
    bpf_ct_release(ct);
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

char _license[] SEC("license") = "GPL";
