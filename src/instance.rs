// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
use std::fmt::Debug;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::RangeInclusive;
use std::os::fd::AsFd;
use std::time::Instant;

use anyhow::{anyhow, Result};
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use ipnet::{IpNet, Ipv4Net};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapFlags, TcHook, TcHookBuilder, TC_EGRESS, TC_INGRESS};
use prefix_trie::{Prefix, PrefixMap, PrefixSet};

use crate::config::{AddressOrMatcher, ConfigDefaults, ConfigExternal, ConfigNetIf, ProtoRange};
use crate::monitor::IfAddresses;
use crate::skel;
use crate::skel::{
    DestConfig as BpfDestConfig, DestFlags, ExternalConfig as BpfExternalConfig, ExternalFlags,
    FullConeNatMaps, FullConeNatSkel, FullConeNatSkelBuilder, OpenFullConeNatSkel,
};
use crate::utils::{self, MapChange, PrefixMapDiff};

#[derive(Debug, Default)]
struct ConstConfig {
    log_level: Option<u8>,
    enable_fib_lookup_src: Option<bool>,
    allow_inbound_icmpx: Option<bool>,
    timeout_fragment: Option<u64>,
    timeout_pkt_min: Option<u64>,
    timeout_pkt_default: Option<u64>,
    timeout_tcp_trans: Option<u64>,
    timeout_tcp_est: Option<u64>,
}
#[derive(Debug)]
struct RuntimeV4Config {
    external_addr: Ipv4Addr,
    dest_config: PrefixMap<Ipv4Net, BpfDestConfig>,
    external_config: PrefixMap<Ipv4Net, BpfExternalConfig>,
}

#[cfg(feature = "ipv6")]
#[derive(Debug)]
struct RuntimeV6Config {
    external_addr: Ipv6Addr,
    dest_config: PrefixMap<Ipv6Net, BpfDestConfig>,
    external_config: PrefixMap<Ipv6Net, BpfExternalConfig>,
}

#[derive(Debug, PartialEq, Eq)]
struct ExternalRanges(Vec<RangeInclusive<u16>>);

#[derive(Debug)]
struct External {
    address: AddressOrMatcher,
    no_snat: bool,
    no_hairpin: bool,
    tcp_ranges: ExternalRanges,
    udp_ranges: ExternalRanges,
    icmp_ranges: ExternalRanges,
    icmp_in_ranges: ExternalRanges,
    icmp_out_ranges: ExternalRanges,
}

#[derive(Debug)]
pub struct InstanceConfig {
    if_index: u32,
    v4_no_snat_dests: Vec<Ipv4Net>,
    #[cfg(feature = "ipv6")]
    v6_no_snat_dests: Vec<Ipv6Net>,
    externals: Vec<External>,
    const_config: ConstConfig,
    runtime_v4_config: RuntimeV4Config,
    #[cfg(feature = "ipv6")]
    runtime_v6_config: RuntimeV6Config,
}

pub struct Instance {
    config: InstanceConfig,
    skel: FullConeNatSkel<'static>,
    attached_ingress_hook: Option<TcHook>,
    attached_egress_hook: Option<TcHook>,
}

impl ConstConfig {
    fn apply(&self, skel: &mut OpenFullConeNatSkel) {
        let rodata = skel.rodata_mut();
        if let Some(log_level) = self.log_level {
            rodata.LOG_LEVEL = log_level;
        }
        if let Some(enable_fib_lookup_src) = self.enable_fib_lookup_src {
            rodata.ENABLE_FIB_LOOKUP_SRC = enable_fib_lookup_src as _;
        }
        if let Some(allow_inbound_icmpx) = self.allow_inbound_icmpx {
            rodata.ALLOW_INBOUND_ICMPX = allow_inbound_icmpx as _;
        }
        if let Some(timeout_fragment) = self.timeout_fragment {
            rodata.TIMEOUT_FRAGMENT = timeout_fragment;
        }
        if let Some(timeout_pkt_min) = self.timeout_pkt_min {
            rodata.TIMEOUT_PKT_MIN = timeout_pkt_min;
        }
        if let Some(timeout_pkt_default) = self.timeout_pkt_default {
            rodata.TIMEOUT_PKT_MIN = timeout_pkt_default;
        }
        if let Some(timeout_tcp_trans) = self.timeout_tcp_trans {
            rodata.TIMEOUT_TCP_TRANS = timeout_tcp_trans;
        }
        if let Some(timeout_tcp_est) = self.timeout_tcp_est {
            rodata.TIMEOUT_TCP_EST = timeout_tcp_est;
        }
    }
}

fn sort_and_merge_ranges(ranges: &[RangeInclusive<u16>]) -> Vec<RangeInclusive<u16>> {
    let mut ranges: Vec<_> = ranges
        .iter()
        .filter(|&range| !range.is_empty())
        .cloned()
        .collect();
    ranges.sort_by_key(|range| *range.start());

    if ranges.len() < 2 {
        return ranges;
    }

    let mut res = Vec::new();
    let mut curr = ranges[0].clone();

    for next in ranges.iter().skip(1) {
        if next.start() > curr.end() {
            res.push(core::mem::replace(&mut curr, next.clone()));
        } else if next.end() > curr.end() {
            curr = *curr.start()..=*next.end();
        }
    }
    res.push(curr);

    res
}

impl ExternalRanges {
    fn try_from(ranges: &[ProtoRange], allow_zero: bool) -> Result<Self> {
        if ranges.len() > skel::MAX_PORT_RANGES {
            return Err(anyhow!(
                "exceed limit of max {} ranges in port ranges list",
                skel::MAX_PORT_RANGES
            ));
        }
        let ranges = ranges
            .iter()
            .map(|range| {
                if !allow_zero && *range.inner.start() == 0 {
                    Err(anyhow!("Port range {} contains zero, which is not allowed in this type of port range", range))
                } else {
                    Ok(range.inner.clone())
                }
            })
            .collect::<Result<_>>()?;
        Ok(Self(ranges))
    }

    fn contains(&self, other: &ExternalRanges) -> bool {
        let this = sort_and_merge_ranges(&self.0);
        let other = sort_and_merge_ranges(&other.0);
        let mut other_it = other.iter().peekable();
        for range in this {
            while let Some(other) = other_it.peek() {
                if other.start() < range.start() {
                    return false;
                }
                if other.start() > range.end() {
                    // continue outer loop
                    break;
                }
                if other.end() > range.end() {
                    return false;
                }
                let _ = other_it.next();
            }
        }
        other_it.peek().is_none()
    }

    fn apply_raw(&self, raw_ranges: &mut skel::PortRanges, raw_len: &mut u8) {
        assert!(self.0.len() <= raw_ranges.len());

        for (idx, raw_range) in raw_ranges.iter_mut().enumerate() {
            if let Some(range) = self.0.get(idx) {
                raw_range.start_port = *range.start();
                raw_range.end_port = *range.end();
            } else {
                raw_range.start_port = 0;
                raw_range.end_port = 0;
            }
        }

        *raw_len = self.0.len() as _;
    }
}

impl External {
    fn try_from(external: &ConfigExternal, defaults: &ConfigDefaults) -> Result<Self> {
        let tcp_ranges = ExternalRanges::try_from(
            external.tcp_ranges.as_ref().unwrap_or(&defaults.tcp_ranges),
            false,
        )?;

        let udp_ranges = ExternalRanges::try_from(
            external.udp_ranges.as_ref().unwrap_or(&defaults.udp_ranges),
            false,
        )?;

        let icmp_ranges = ExternalRanges::try_from(
            external
                .icmp_ranges
                .as_ref()
                .unwrap_or(&defaults.icmp_ranges),
            true,
        )?;

        let icmp_in_ranges = if icmp_ranges.0.is_empty() {
            ExternalRanges(Vec::new())
        } else {
            ExternalRanges::try_from(
                external
                    .icmp_in_ranges
                    .as_ref()
                    .unwrap_or(&defaults.icmp_in_ranges),
                true,
            )?
        };

        let icmp_out_ranges = if icmp_ranges.0.is_empty() {
            ExternalRanges(Vec::new())
        } else {
            ExternalRanges::try_from(
                external
                    .icmp_out_ranges
                    .as_ref()
                    .unwrap_or(&defaults.icmp_out_ranges),
                true,
            )?
        };

        if !icmp_ranges.contains(&icmp_in_ranges) {
            return Err(anyhow!(
                "ICMP ranges {:?} not fully include ICMP inbound ranges {:?}",
                icmp_ranges,
                icmp_in_ranges
            ));
        }
        if !icmp_ranges.contains(&icmp_out_ranges) {
            return Err(anyhow!(
                "ICMP ranges {:?} not fully include ICMP outbound ranges {:?}",
                icmp_ranges,
                icmp_in_ranges
            ));
        }

        Ok(Self {
            address: external.address,
            no_snat: external.no_snat,
            no_hairpin: external.no_hairpin,
            tcp_ranges,
            udp_ranges,
            icmp_ranges,
            icmp_in_ranges,
            icmp_out_ranges,
        })
    }
}

trait RuntimeConfig {
    type Addr: Copy + PartialEq;
    type Prefix: Copy + Prefix + Debug;

    fn external_addr(&self) -> &Self::Addr;
    fn external_addr_mut(&mut self) -> &mut Self::Addr;

    fn dest_config(&self) -> &PrefixMap<Self::Prefix, BpfDestConfig>;
    fn dest_config_mut(&mut self) -> &mut PrefixMap<Self::Prefix, BpfDestConfig>;

    fn external_config(&self) -> &PrefixMap<Self::Prefix, BpfExternalConfig>;
    fn external_config_mut(&mut self) -> &mut PrefixMap<Self::Prefix, BpfExternalConfig>;

    fn prefix_from_addr(addr: Self::Addr) -> Self::Prefix;
    fn addr_from_prefix(prefix: Self::Prefix) -> Self::Addr;
    fn addr_from_ip_addr(ip_addr: IpAddr) -> Option<Self::Addr>;
    fn ip_addr_from_addr(addr: Self::Addr) -> IpAddr;

    fn with_lpm_key_bytes<R, F: FnOnce(&[u8]) -> R>(prefix: Self::Prefix, f: F) -> R;

    fn apply_external_addr(&self, skel: &mut FullConeNatSkel);
    fn skel_map_dest_config<'a>(maps: &'a FullConeNatMaps<'_>) -> &'a libbpf_rs::Map;
    fn skel_map_external_config<'a>(maps: &'a FullConeNatMaps<'_>) -> &'a libbpf_rs::Map;

    fn init(
        &mut self,
        no_snat_dests: &[Self::Prefix],
        externals: &[External],
        addresses: &[Self::Addr],
    ) {
        let mut external_addr: Option<Self::Addr> = None;

        for network in no_snat_dests {
            let dest_value = self.dest_config_mut().entry(*network).or_default();
            dest_value.flags.insert(DestFlags::NO_SNAT);
        }

        let mut addresses_set =
            PrefixSet::from_iter(addresses.iter().copied().map(Self::prefix_from_addr));

        for external in externals {
            let mut matches = Vec::new();
            match external.address {
                AddressOrMatcher::Static { address } => {
                    if let Some(address) = Self::addr_from_ip_addr(address) {
                        matches.push(Self::prefix_from_addr(address));
                    }
                }
                AddressOrMatcher::Matcher { match_address } => {
                    for address in addresses_set.iter() {
                        if match_address
                            .contains(&Self::ip_addr_from_addr(Self::addr_from_prefix(*address)))
                        {
                            matches.push(*address);
                        }
                    }
                }
            }

            for address in matches.iter() {
                addresses_set.remove(address);
            }

            if external_addr.is_none() && !external.no_snat {
                if let Some(first) = matches.first() {
                    external_addr = Some(Self::addr_from_prefix(*first));
                }
            }

            for network in matches {
                let dest_value = self.dest_config_mut().entry(network).or_default();
                dest_value
                    .flags
                    .set(DestFlags::HAIRPIN, !external.no_hairpin);

                let ext_value = self.external_config_mut().entry(network).or_default();
                ext_value
                    .flags
                    .set(ExternalFlags::NO_SNAT, external.no_snat);

                if external.no_snat {
                    continue;
                }

                external
                    .tcp_ranges
                    .apply_raw(&mut ext_value.tcp_range, &mut ext_value.tcp_range_len);
                external
                    .udp_ranges
                    .apply_raw(&mut ext_value.udp_range, &mut ext_value.udp_range_len);
                external
                    .icmp_ranges
                    .apply_raw(&mut ext_value.icmp_range, &mut ext_value.icmp_range_len);
                external.icmp_in_ranges.apply_raw(
                    &mut ext_value.icmp_in_range,
                    &mut ext_value.icmp_in_range_len,
                );
                external.icmp_out_ranges.apply_raw(
                    &mut ext_value.icmp_out_range,
                    &mut ext_value.icmp_out_range_len,
                );
            }
        }

        if let Some(external_addr) = external_addr {
            *self.external_addr_mut() = external_addr;
        }
    }

    fn apply(&self, old: Option<&Self>, skel: &mut FullConeNatSkel) -> Result<()> {
        let handle_dest_change = |skel: &mut FullConeNatSkel, change| -> Result<()> {
            let maps = skel.maps();
            let map_dest_config = Self::skel_map_dest_config(&maps);
            match change {
                MapChange::Insert(k, v) | MapChange::Update(k, v) => {
                    eprintln!("insert/update dest {:?}", k);
                    Self::with_lpm_key_bytes(*k, |k| {
                        map_dest_config.update(k, bytemuck::bytes_of(v), MapFlags::ANY)
                    })?;
                }
                MapChange::Delete(k) => {
                    eprintln!("delete dest {:?}", k);
                    Self::with_lpm_key_bytes(*k, |k| map_dest_config.delete(k))?;
                }
            }
            Ok(())
        };

        let handle_external_change = |skel: &mut FullConeNatSkel, change| -> Result<()> {
            match change {
                MapChange::Insert(k, v) => {
                    eprintln!("insert external {:?}", k);

                    let maps = skel.maps();
                    let map_ext_config = Self::skel_map_external_config(&maps);
                    Self::with_lpm_key_bytes(*k, |k| {
                        map_ext_config.update(k, bytemuck::bytes_of(v), MapFlags::NO_EXIST)
                    })?;
                }
                MapChange::Update(k, v) => {
                    eprintln!("update external {:?}", k);

                    with_skel_deleting(skel, |skel| -> Result<()> {
                        remove_binding_and_ct_entires(
                            skel,
                            Self::ip_addr_from_addr(Self::addr_from_prefix(*k)),
                        )?;

                        let maps = skel.maps();
                        let map_ext_config = Self::skel_map_external_config(&maps);
                        Self::with_lpm_key_bytes(*k, |k| {
                            map_ext_config.update(k, bytemuck::bytes_of(v), MapFlags::EXIST)
                        })?;

                        Ok(())
                    })?;
                }
                MapChange::Delete(k) => {
                    eprintln!("delete external {:?}", k);

                    with_skel_deleting(skel, |skel| -> Result<()> {
                        let maps = skel.maps();
                        let map_ext_config = Self::skel_map_external_config(&maps);
                        Self::with_lpm_key_bytes(*k, |k| map_ext_config.delete(k))?;

                        remove_binding_and_ct_entires(
                            skel,
                            Self::ip_addr_from_addr(Self::addr_from_prefix(*k)),
                        )
                    })?;
                }
            }
            Ok(())
        };

        if let Some(old) = old {
            let dest_config_diff = PrefixMapDiff::new(old.dest_config(), self.dest_config());
            let external_config_diff =
                PrefixMapDiff::new(old.external_config(), self.external_config());
            for change in dest_config_diff {
                handle_dest_change(skel, change)?;
            }
            for change in external_config_diff {
                handle_external_change(skel, change)?;
            }
            if old.external_addr() != self.external_addr() {
                self.apply_external_addr(skel);
            }
        } else {
            for change in self
                .dest_config()
                .iter()
                .map(|(k, v)| MapChange::Insert(k, v))
            {
                handle_dest_change(skel, change)?;
            }

            for change in self
                .external_config()
                .iter()
                .map(|(k, v)| MapChange::Insert(k, v))
            {
                handle_external_change(skel, change)?;
            }

            self.apply_external_addr(skel);
        }

        Ok(())
    }
}

impl RuntimeConfig for RuntimeV4Config {
    type Addr = Ipv4Addr;
    type Prefix = Ipv4Net;

    fn external_addr(&self) -> &Self::Addr {
        &self.external_addr
    }
    fn external_addr_mut(&mut self) -> &mut Self::Addr {
        &mut self.external_addr
    }

    fn dest_config(&self) -> &PrefixMap<Self::Prefix, BpfDestConfig> {
        &self.dest_config
    }
    fn dest_config_mut(&mut self) -> &mut PrefixMap<Self::Prefix, BpfDestConfig> {
        &mut self.dest_config
    }

    fn external_config(&self) -> &PrefixMap<Self::Prefix, BpfExternalConfig> {
        &self.external_config
    }
    fn external_config_mut(&mut self) -> &mut PrefixMap<Self::Prefix, BpfExternalConfig> {
        &mut self.external_config
    }

    fn prefix_from_addr(addr: Self::Addr) -> Self::Prefix {
        utils::ipv4_addr_to_net(addr)
    }

    fn addr_from_prefix(prefix: Self::Prefix) -> Self::Addr {
        prefix.addr()
    }

    fn addr_from_ip_addr(ip_addr: IpAddr) -> Option<Self::Addr> {
        if let IpAddr::V4(addr) = ip_addr {
            Some(addr)
        } else {
            None
        }
    }

    fn ip_addr_from_addr(addr: Self::Addr) -> IpAddr {
        IpAddr::V4(addr)
    }

    fn with_lpm_key_bytes<R, F: FnOnce(&[u8]) -> R>(prefix: Self::Prefix, f: F) -> R {
        let key: skel::Ipv4LpmKey = prefix.into();
        f(bytemuck::bytes_of(&key))
    }

    fn apply_external_addr(&self, skel: &mut FullConeNatSkel) {
        eprintln!("setting external address {:?}", self.external_addr);
        skel.data_mut().g_ipv4_external_addr = bytemuck::cast(self.external_addr.octets());
    }

    fn skel_map_dest_config<'a>(maps: &'a FullConeNatMaps<'_>) -> &'a libbpf_rs::Map {
        maps.map_ipv4_dest_config()
    }

    fn skel_map_external_config<'a>(maps: &'a FullConeNatMaps<'_>) -> &'a libbpf_rs::Map {
        maps.map_ipv4_external_config()
    }
}

#[cfg(feature = "ipv6")]
impl RuntimeConfig for RuntimeV6Config {
    type Addr = Ipv6Addr;
    type Prefix = Ipv6Net;

    fn external_addr(&self) -> &Self::Addr {
        &self.external_addr
    }
    fn external_addr_mut(&mut self) -> &mut Self::Addr {
        &mut self.external_addr
    }

    fn dest_config(&self) -> &PrefixMap<Self::Prefix, BpfDestConfig> {
        &self.dest_config
    }
    fn dest_config_mut(&mut self) -> &mut PrefixMap<Self::Prefix, BpfDestConfig> {
        &mut self.dest_config
    }

    fn external_config(&self) -> &PrefixMap<Self::Prefix, BpfExternalConfig> {
        &self.external_config
    }
    fn external_config_mut(&mut self) -> &mut PrefixMap<Self::Prefix, BpfExternalConfig> {
        &mut self.external_config
    }

    fn prefix_from_addr(addr: Self::Addr) -> Self::Prefix {
        utils::ipv6_addr_to_net(addr)
    }

    fn addr_from_prefix(prefix: Self::Prefix) -> Self::Addr {
        prefix.addr()
    }

    fn addr_from_ip_addr(ip_addr: IpAddr) -> Option<Self::Addr> {
        if let IpAddr::V6(addr) = ip_addr {
            Some(addr)
        } else {
            None
        }
    }

    fn ip_addr_from_addr(addr: Self::Addr) -> IpAddr {
        IpAddr::V6(addr)
    }

    fn with_lpm_key_bytes<R, F: FnOnce(&[u8]) -> R>(prefix: Self::Prefix, f: F) -> R {
        let key: skel::Ipv6LpmKey = prefix.into();
        f(bytemuck::bytes_of(&key))
    }

    fn apply_external_addr(&self, skel: &mut FullConeNatSkel) {
        eprintln!("setting external address {:?}", self.external_addr);
        skel.data_mut().g_ipv6_external_addr = bytemuck::cast(self.external_addr.octets());
    }

    fn skel_map_dest_config<'a>(maps: &'a FullConeNatMaps<'_>) -> &'a libbpf_rs::Map {
        maps.map_ipv4_dest_config()
    }

    fn skel_map_external_config<'a>(maps: &'a FullConeNatMaps<'_>) -> &'a libbpf_rs::Map {
        maps.map_ipv4_external_config()
    }
}

impl RuntimeV4Config {
    fn from(no_snat_dests: &[Ipv4Net], externals: &[External], addresses: &[Ipv4Addr]) -> Self {
        let mut this = Self {
            external_addr: Ipv4Addr::UNSPECIFIED,
            dest_config: Default::default(),
            external_config: Default::default(),
        };
        Self::init(&mut this, no_snat_dests, externals, addresses);
        this
    }
}

#[cfg(feature = "ipv6")]
impl RuntimeV6Config {
    fn from(no_snat_dests: &[Ipv6Net], externals: &[External], addresses: &[Ipv6Addr]) -> Self {
        let mut this = Self {
            external_addr: Ipv6Addr::UNSPECIFIED,
            dest_config: Default::default(),
            external_config: Default::default(),
        };
        Self::init(&mut this, no_snat_dests, externals, addresses);
        this
    }
}

impl InstanceConfig {
    pub fn try_from(
        if_index: u32,
        if_config: &ConfigNetIf,
        defaults: &ConfigDefaults,
        addresses: &IfAddresses,
    ) -> Result<Self> {
        let const_config = ConstConfig {
            // defaults to disable logging
            log_level: Some(if_config.bpf_log_level.unwrap_or(0).min(5)),
            enable_fib_lookup_src: if_config.bpf_fib_lookup_external,
            allow_inbound_icmpx: if_config.allow_inbound_icmpx,
            timeout_fragment: if_config.timeout_fragment.map(Into::into),
            timeout_pkt_min: if_config.timeout_pkt_min.map(Into::into),
            timeout_pkt_default: if_config.timeout_pkt_default.map(Into::into),
            timeout_tcp_est: if_config.timeout_tcp_est.map(Into::into),
            timeout_tcp_trans: if_config.timeout_tcp_trans.map(Into::into),
        };

        let mut default_externals = Vec::new();
        if if_config.default_externals {
            if if_config.nat44 {
                default_externals.push(ConfigExternal::match_any_ipv4())
            }
            if if_config.nat66 {
                default_externals.push(ConfigExternal::match_any_ipv6())
            }
        }
        let externals = if_config
            .externals
            .iter()
            .chain(&default_externals)
            .map(|external| External::try_from(external, defaults))
            .collect::<Result<Vec<_>>>()?;

        fn unwrap_v4(network: &IpNet) -> Option<Ipv4Net> {
            if let IpNet::V4(network) = network {
                Some(*network)
            } else {
                None
            }
        }

        let v4_no_snat_dests = if_config
            .no_snat_dests
            .iter()
            .filter_map(unwrap_v4)
            .collect::<Vec<_>>();

        let runtime_v4_config =
            RuntimeV4Config::from(&v4_no_snat_dests, &externals, &addresses.ipv4);

        #[cfg(feature = "ipv6")]
        fn unwrap_v6(network: &IpNet) -> Option<Ipv6Net> {
            if let IpNet::V6(network) = network {
                Some(*network)
            } else {
                None
            }
        }

        #[cfg(feature = "ipv6")]
        let v6_no_snat_dests = if_config
            .no_snat_dests
            .iter()
            .filter_map(unwrap_v6)
            .collect::<Vec<_>>();
        #[cfg(feature = "ipv6")]
        let runtime_v6_config =
            RuntimeV6Config::from(&v6_no_snat_dests, &externals, &addresses.ipv6);

        Ok(Self {
            if_index,
            v4_no_snat_dests,
            #[cfg(feature = "ipv6")]
            v6_no_snat_dests,
            externals,
            const_config,
            runtime_v4_config,
            #[cfg(feature = "ipv6")]
            runtime_v6_config,
        })
    }

    pub fn is_static(&self) -> bool {
        self.externals
            .iter()
            .all(|external| matches!(external.address, AddressOrMatcher::Static { .. }))
    }

    pub fn load(self) -> Result<Instance> {
        let mut skel_builder = FullConeNatSkelBuilder::default();

        skel_builder.obj_builder.debug(true);

        let mut open_skel = skel_builder.open()?;

        self.const_config.apply(&mut open_skel);

        let start = Instant::now();
        let mut skel = open_skel.load()?;
        eprintln!("eBPF programs loaded in {:?}", start.elapsed());

        self.runtime_v4_config.apply(None, &mut skel)?;
        #[cfg(feature = "ipv6")]
        self.runtime_v6_config.apply(None, &mut skel)?;

        Ok(Instance {
            config: self,
            skel,
            attached_egress_hook: None,
            attached_ingress_hook: None,
        })
    }
}

impl Instance {
    pub fn reconfigure_v4_addresses(&mut self, addresses: &[Ipv4Addr]) -> Result<()> {
        let new = RuntimeV4Config::from(
            &self.config.v4_no_snat_dests,
            &self.config.externals,
            addresses,
        );

        new.apply(Some(&self.config.runtime_v4_config), &mut self.skel)?;
        self.config.runtime_v4_config = new;

        Ok(())
    }

    #[cfg(feature = "ipv6")]
    pub fn reconfigure_v6_addresses(&mut self, addresses: &[Ipv6Addr]) -> Result<()> {
        let new = RuntimeV6Config::from(
            &self.config.v6_no_snat_dests,
            &self.config.externals,
            addresses,
        );

        new.apply(Some(&self.config.runtime_v6_config), &mut self.skel)?;
        self.config.runtime_v6_config = new;

        Ok(())
    }

    fn ingress_tc_hook(&self) -> TcHook {
        let progs = self.skel.progs();
        TcHookBuilder::new(progs.ingress_rev_snat().as_fd())
            .ifindex(self.config.if_index as _)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_INGRESS)
    }

    fn egress_tc_hook(&self) -> TcHook {
        let progs = self.skel.progs();
        TcHookBuilder::new(progs.egress_snat().as_fd())
            .ifindex(self.config.if_index as _)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_EGRESS)
    }

    pub fn attach(&mut self) -> Result<()> {
        self.attached_ingress_hook = Some(self.ingress_tc_hook().create()?.attach()?);
        self.attached_egress_hook = Some(self.egress_tc_hook().attach()?);
        Ok(())
    }

    pub fn detach(&mut self) -> Result<()> {
        if let Some(mut hook) = self.attached_egress_hook.take() {
            hook.detach()?;
        }
        if let Some(mut hook) = self.attached_ingress_hook.take() {
            hook.detach()?;
        }

        Ok(())
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

fn with_skel_deleting<T, F: FnOnce(&mut FullConeNatSkel) -> T>(
    skel: &mut FullConeNatSkel,
    f: F,
) -> T {
    skel.data_mut().g_deleting_map_entires = 1;

    // Wait for 1ms and expecting all previous BPF program calls
    // that had not seen g_deleting_map_entires=1 have finished,
    // so binding map and CT map become stable.
    std::thread::sleep(std::time::Duration::from_millis(1));

    let res = f(skel);

    skel.data_mut().g_deleting_map_entires = 0;

    res
}

fn remove_binding_and_ct_entires(skel: &FullConeNatSkel, external_addr: IpAddr) -> Result<()> {
    use skel::{BindingFlags, InetAddr, MapBindingKey, MapBindingValue, MapCtKey};

    let maps = skel.maps();
    let map_binding = maps.map_binding();
    let map_ct = maps.map_ct();

    let addr_flag = if external_addr.is_ipv4() {
        BindingFlags::ADDR_IPV4
    } else {
        BindingFlags::ADDR_IPV6
    };
    let external_addr: InetAddr = external_addr.into();

    let mut to_delete_binding_keys = Vec::new();
    for binding_key_raw in map_binding.keys() {
        let binding_key: &MapBindingKey = bytemuck::from_bytes(&binding_key_raw);
        if binding_key.flags.contains(BindingFlags::ORIG_DIR) {
            if let Some(binding_value_raw) = map_binding.lookup(&binding_key_raw, MapFlags::ANY)? {
                let binding_value: &MapBindingValue = bytemuck::from_bytes(&binding_value_raw);
                if binding_value.flags.contains(addr_flag) && binding_value.to_addr == external_addr
                {
                    to_delete_binding_keys.extend(binding_key_raw);
                }
            }
        } else if binding_key.flags.contains(addr_flag) && binding_key.from_addr == external_addr {
            to_delete_binding_keys.extend(binding_key_raw);
        }
    }

    map_binding.delete_batch(
        &to_delete_binding_keys,
        (to_delete_binding_keys.len() / core::mem::size_of::<MapBindingKey>()) as _,
        MapFlags::ANY,
        MapFlags::ANY,
    )?;

    let mut to_delete_ct_keys = Vec::new();
    for ct_key_raw in map_ct.keys() {
        let ct_key: &MapCtKey = bytemuck::from_bytes(&ct_key_raw);
        if ct_key.flags.contains(addr_flag) && ct_key.external.src_addr == external_addr {
            to_delete_ct_keys.extend(ct_key_raw);
        }
    }

    map_ct.delete_batch(
        &to_delete_ct_keys,
        (to_delete_ct_keys.len() / core::mem::size_of::<MapCtKey>()) as _,
        MapFlags::ANY,
        MapFlags::ANY,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_range() {
        let ranges_a = vec![
            ProtoRange { inner: 200..=300 },
            ProtoRange { inner: 0..=100 },
            ProtoRange { inner: 50..=150 },
            ProtoRange { inner: 250..=290 },
        ];
        let ranges_a = ExternalRanges::try_from(&ranges_a, true).unwrap();
        assert_eq!(vec![0..=150, 200..=300], sort_and_merge_ranges(&ranges_a.0));
        assert!(ranges_a.contains(&ranges_a));

        let ranges_b = vec![ProtoRange { inner: 0..=100 }];
        let ranges_b = ExternalRanges::try_from(&ranges_b, true).unwrap();
        assert!(ranges_a.contains(&ranges_b));

        let ranges_c = vec![ProtoRange { inner: 120..=220 }];
        let ranges_c = ExternalRanges::try_from(&ranges_c, true).unwrap();
        assert!(!ranges_a.contains(&ranges_c));

        let ranges_d = vec![ProtoRange { inner: 0..=1 }];
        let ranges_d = ExternalRanges::try_from(&ranges_d, false);
        assert!(ranges_d.is_err())
    }
}
