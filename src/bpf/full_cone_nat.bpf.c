// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#include "full_cone_nat.h"

#define DEFAULT_MAX_ENTRIES 65536 * 4

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mapping_key);
    __type(value, struct mapping_value);
    // upper bound: <number of interfaces attached> * <number of ip addresses> *
    // 65536
    __uint(max_entries, DEFAULT_MAX_ENTRIES);
} mapping_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_key);
    __type(value, struct conn_value);
    __uint(max_entries, DEFAULT_MAX_ENTRIES);
} conn_table SEC(".maps");

static int get_tuple(const struct __sk_buff *skb, bool reverse,
                     struct bpf_sock_tuple *p_tuple, bool *p_is_ipv4,
                     u8 *p_l4_proto) {
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
            __builtin_memcpy(p_tuple->ipv6.saddr, ip6h->daddr.in6_u.u6_addr32,
                             sizeof(p_tuple->ipv6.saddr));
            __builtin_memcpy(p_tuple->ipv6.daddr, ip6h->saddr.in6_u.u6_addr32,
                             sizeof(p_tuple->ipv6.daddr));
        } else {
            __builtin_memcpy(p_tuple->ipv6.saddr, ip6h->saddr.in6_u.u6_addr32,
                             sizeof(p_tuple->ipv6.saddr));
            __builtin_memcpy(p_tuple->ipv6.daddr, ip6h->daddr.in6_u.u6_addr32,
                             sizeof(p_tuple->ipv6.daddr));
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

static inline bool check_mapping_active(struct __sk_buff *skb,
                                        struct mapping_key *key,
                                        struct mapping_value *m, bool is_ipv4,
                                        u8 l4proto) {
    bpf_spin_lock(&m->lock);
    int len = m->len;
    bpf_spin_unlock(&m->lock);

    int i = 0;
    bpf_for(i, 0, len) {
        bpf_printk("    looping %d", i);
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
            struct nf_conntrack_tuple *orig_tuple = &origin->orig_tuple;
            struct conn_key c_key = {
                .origin =
                    {
                        .saddr = orig_tuple->src.u3,
                        .sport = orig_tuple->src.u.all,
                        .daddr = orig_tuple->dst.u3,
                        .dport = orig_tuple->dst.u.all,
                    },
                .m_key = *key,
            };
            bpf_printk("    clean expired mapping");
            if (bpf_map_delete_elem(&conn_table, &c_key) != 0) {
                bpf_printk("    failed to delete conn");
            }
            bpf_obj_drop(origin);
            continue;
        }

        bpf_spin_lock(&m->lock);
        if (bpf_list_push_back(&m->origin_list_head, &origin->node) == 0) {
            m->len++;
        }
        bpf_spin_unlock(&m->lock);

        if (active) {
            return true;
        }
    }

    bpf_spin_lock(&m->lock);
    len = m->len;
    bpf_spin_unlock(&m->lock);

    if (len != 0) {
        bpf_printk("    racing, new origin added");
    }

    return false;
}

static inline bool push_mapping_origin(struct mapping_key *m_key,
                                       struct mapping_value *m,
                                       struct nf_conntrack_tuple *orig_tuple,
                                       bool update) {
    struct conn_key c_key = {
        .origin =
            {
                .saddr = orig_tuple->src.u3,
                .sport = orig_tuple->src.u.all,
                .daddr = orig_tuple->dst.u3,
                .dport = orig_tuple->dst.u.all,
            },
        .m_key = *m_key,
    };

    struct conn_value *c = bpf_map_lookup_elem(&conn_table, &c_key);
    if (c) {
        if (!update) {
            bpf_printk("    origin already added, racing");
        }
        return update;
    }

    struct conn_value c_new = {0};
    struct mapping_origin *origin = bpf_obj_new(typeof(*origin));
    if (!origin) {
        return false;
    }
    nf_ct_tuple_copy(&origin->orig_tuple, orig_tuple);

    bpf_spin_lock(&m->lock);
    if (bpf_list_push_back(&m->origin_list_head, &origin->node) == 0) {
        m->len++;
    } else {
        bpf_spin_unlock(&m->lock);
        return false;
    }
    bpf_spin_unlock(&m->lock);

    if (bpf_map_update_elem(&conn_table, &c_key, &c_new, BPF_NOEXIST) != 0) {
        bpf_printk("conn item insertion full or racing");
        return false;
    }

    return true;
}

SEC("tc")
int ingress_dnat(struct __sk_buff *skb) {
    struct bpf_sock_tuple bpf_tuple;
    bool is_ipv4;
    u8 l4proto;

    int ret = get_tuple(skb, false, &bpf_tuple, &is_ipv4, &l4proto);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_printk("invalid packet");
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

    bpf_printk("ingress no ct, is_ipv4:%d", is_ipv4);

    struct mapping_key key = {
        .ifindex = skb->ifindex,
        .ext_addr.all = {0},
    };
    if (is_ipv4) {
        key.ext_addr.ip = bpf_tuple.ipv4.daddr;
        key.ext_port = bpf_tuple.ipv4.dport;
    } else {
        __builtin_memcpy(key.ext_addr.ip6, bpf_tuple.ipv6.daddr,
                         sizeof(key.ext_addr.ip6));
        key.ext_port = bpf_tuple.ipv6.dport;
    }

    struct mapping_value *m = bpf_map_lookup_elem(&mapping_table, &key);
    if (!m) {
        // SNAT has not seen from egress, bail out
        return TC_ACT_UNSPEC;
    }
    if (!check_mapping_active(skb, &key, m, is_ipv4, l4proto)) {
        bpf_printk("    mapping not active");
        bpf_map_delete_elem(&mapping_table, &key);
        return TC_ACT_UNSPEC;
    }

    bpf_printk("    ingress found match");

    struct bpf_sock_tuple intern_tuple;
    if (is_ipv4) {
        intern_tuple.ipv4.saddr = m->orig_addr.ip;
        intern_tuple.ipv4.sport = m->orig_port;
        intern_tuple.ipv4.daddr = bpf_tuple.ipv4.saddr;
        intern_tuple.ipv4.dport = bpf_tuple.ipv4.sport;
    } else {
        __builtin_memcpy(intern_tuple.ipv6.saddr, m->orig_addr.ip6,
                         sizeof(intern_tuple.ipv6.saddr));
        intern_tuple.ipv6.sport = m->orig_port;
        __builtin_memcpy(intern_tuple.ipv6.daddr, bpf_tuple.ipv6.saddr,
                         sizeof(intern_tuple.ipv6.daddr));
        intern_tuple.ipv6.dport = bpf_tuple.ipv6.sport;
    }

    struct bpf_ct_opts ct_opts_2 = {.netns_id = -1, .l4proto = l4proto};

    struct nf_conn___init *cf_conn_init = bpf_skb_ct_alloc(
        skb, &intern_tuple,
        is_ipv4 ? sizeof(bpf_tuple.ipv4) : sizeof(bpf_tuple.ipv6), &ct_opts_2,
        NF_BPF_CT_OPTS_SZ);
    if (!cf_conn_init) {
        return TC_ACT_UNSPEC;
    }

    union nf_inet_addr ext_addr = {0};
    if (is_ipv4) {
        ext_addr.ip = bpf_tuple.ipv4.daddr;
    } else {
        __builtin_memcpy(ext_addr.ip6, bpf_tuple.ipv6.daddr,
                         sizeof(ext_addr.ip6));
    }

    // Fake a internal initialed SNAT connection with the same source mapping we
    // collected at egress.
    // We do SNAT instead of DNAT here because nf_nat module
    // would reuse active source mapping(including the one we added here)
    // for new SNATs (search "nat_bysource" in kernel source). However, If we
    // use DNAT, the same SNAT source mapping would not be guaranteed for new
    // connections originated from internal if the original SNAT conntrack seen
    // from egress expires, as there is no other conntrack that share the same
    // source mapping keep the mapping alive.
    bpf_ct_set_nat_info(cf_conn_init, &ext_addr, bpf_ntohs(key.ext_port),
                        NF_NAT_MANIP_SRC);
    bpf_ct_set_timeout(cf_conn_init, 30000);

    struct nf_conn *nf_conn = bpf_ct_insert_entry(cf_conn_init);
    if (!nf_conn) {
        return TC_ACT_UNSPEC;
    }
    bpf_ct_change_status(nf_conn, IPS_SEEN_REPLY);

    if (!push_mapping_origin(
            &key, m, &nf_conn->tuplehash[IP_CT_DIR_ORIGINAL].tuple, false)) {
        goto ct_done;
    }

    if (is_ipv4)
        bpf_printk("    ingress mapping added %x:%d len:%d",
                   bpf_ntohl(m->orig_addr.ip), m->orig_port, m->len);

ct_done:
    bpf_ct_release(nf_conn);
    return TC_ACT_UNSPEC;
}

SEC("tc")
int egress_collect_snat(struct __sk_buff *skb) {
    struct bpf_sock_tuple bpf_tuple;
    bool is_ipv4;
    u8 l4proto;

    // build tuple for reply direction
    int ret = get_tuple(skb, true, &bpf_tuple, &is_ipv4, &l4proto);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_printk("invalid packet");
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
    struct nf_conntrack_tuple *orig_tuple =
        &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

    // On egress side we only care connections initiated from internal
    if (ct_opts.dir != IP_CT_DIR_REPLY) {
        goto ct_done;
    }

    if ((ct->status & (IPS_SRC_NAT | IPS_DYING)) != IPS_SRC_NAT) {
        goto ct_done;
    }

    struct mapping_key key = {
        .ifindex = skb->ifindex,
        .ext_port = tuple->dst.u.all,
        .ext_addr = tuple->dst.u3,
    };

    bool add_new_mapping = true;
    struct mapping_value *m = bpf_map_lookup_elem(&mapping_table, &key);
    if (m) {
        bpf_printk("    found old mapping");
        add_new_mapping =
            !(m->orig_port == orig_tuple->src.u.all &&
              __builtin_memcmp(m->orig_addr.all, orig_tuple->src.u3.all,
                               sizeof(m->orig_addr.all)) == 0);
        if (add_new_mapping) {
            bpf_printk("    delete old mapping");
            bpf_map_delete_elem(&mapping_table, &key);
        } else if (!push_mapping_origin(&key, m, orig_tuple, true)) {
            goto ct_done;
        }
    }

    if (add_new_mapping) {
        bpf_printk("add new mapping");
        struct mapping_value m_new = {
            .key = key,
            .is_ipv4 = is_ipv4,
            .orig_addr = orig_tuple->src.u3,
            .orig_port = orig_tuple->src.u.all,
            .len = 0,
        };

        // XXX: handle concurrences?
        if (bpf_map_update_elem(&mapping_table, &key, &m_new, BPF_NOEXIST) !=
            0) {
            bpf_printk("mapping item insertion full or racing");
            goto ct_done;
        }
        m = bpf_map_lookup_elem(&mapping_table, &key);
        if (!m) {
            bpf_printk("racing, item got removed");
            goto ct_done;
        }

        if (!push_mapping_origin(&key, m, orig_tuple, false)) {
            goto ct_done;
        }
    }

ct_done:
    bpf_ct_release(ct);
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
