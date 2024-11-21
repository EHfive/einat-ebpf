// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::{Debug, Display};
use std::ops::RangeInclusive;

use anyhow::{anyhow, Result};
// avoid reinventing the wheel, this would not increase binary size much
use aya::util::KernelVersion;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use ipnet::{IpNet, Ipv4Net};
use prefix_trie::map::Entry;
use prefix_trie::{Prefix, PrefixMap, PrefixSet};
use tracing::warn;

use crate::config::{AddressOrMatcher, ConfigDefaults, ConfigExternal, ConfigNetIf, ProtoRange};
use crate::route::IfAddresses;
use crate::skel::einat;
use crate::skel::einat::types;
use crate::skel::{DestConfig, ExternalConfig};
use crate::utils::{IpAddress, IpNetwork};

#[derive(Debug, Default)]
pub struct LoadConfig(pub(super) einat::EinatConstConfig);

pub trait InetPrefix:
    IpNetwork<Addr: Display>
    + IpAddress<Data: for<'a> TryFrom<&'a [u8], Error: Debug>>
    + Copy
    + Prefix
    + PartialEq
    + Display
{
}

impl InetPrefix for Ipv4Net {}
#[cfg(feature = "ipv6")]
impl InetPrefix for Ipv6Net {}

#[derive(Debug, Default)]
pub struct InetConfig<P: InetPrefix> {
    pub external_addr: P,
    pub dest_config: PrefixMap<P, DestConfig>,
    pub external_config: PrefixMap<P, ExternalConfig>,
}

#[derive(Debug, Default)]
pub struct RuntimeConfig {
    pub v4: InetConfig<Ipv4Net>,
    #[cfg(feature = "ipv6")]
    pub v6: InetConfig<Ipv6Net>,
}

pub struct RuntimeConfigEval {
    v4_no_snat_dests: Vec<Ipv4Net>,
    #[cfg(feature = "ipv6")]
    v6_no_snat_dests: Vec<Ipv6Net>,
    externals: Vec<External>,
}

#[derive(Debug, PartialEq, Eq)]
struct ExternalRanges(Vec<RangeInclusive<u16>>);

#[derive(Debug)]
struct External {
    address: AddressOrMatcher,
    is_internal: bool,
    no_snat: bool,
    no_hairpin: bool,
    tcp_ranges: ExternalRanges,
    udp_ranges: ExternalRanges,
    icmp_ranges: ExternalRanges,
    icmp_in_ranges: ExternalRanges,
    icmp_out_ranges: ExternalRanges,
}

impl LoadConfig {
    pub fn from(config: &ConfigNetIf, has_eth_encap: bool) -> Self {
        let nat44 = config.nat44();
        let nat66 = config.nat66();
        let nat64 = config.nat64();

        let mut ro_data = einat::EinatRoData {
            HAS_ETH_ENCAP: has_eth_encap as _,
            INGRESS_IPV4: (nat44 || nat64) as _,
            EGRESS_IPV4: nat44 as _,
            INGRESS_IPV6: nat66 as _,
            EGRESS_IPV6: (nat66 || nat64) as _,
            ..Default::default()
        };

        let bpf_fib_lookup_external = config.bpf_fib_lookup_external.unwrap_or_else(|| {
            if let Ok(v) = KernelVersion::current() {
                v >= KernelVersion::new(6, 7, 0)
            } else {
                false
            }
        });
        ro_data.ENABLE_FIB_LOOKUP_SRC = bpf_fib_lookup_external as _;

        if let Some(v) = config.bpf_log_level {
            ro_data.LOG_LEVEL = v;
        }
        if let Some(v) = config.allow_inbound_icmpx {
            ro_data.ALLOW_INBOUND_ICMPX = v as _;
        }
        if let Some(v) = config.timeout_fragment {
            ro_data.TIMEOUT_FRAGMENT = v.0;
        }
        if let Some(v) = config.timeout_pkt_min {
            ro_data.TIMEOUT_PKT_MIN = v.0;
        }
        if let Some(v) = config.timeout_pkt_default {
            ro_data.TIMEOUT_PKT_MIN = v.0;
        }
        if let Some(v) = config.timeout_tcp_trans {
            ro_data.TIMEOUT_TCP_TRANS = v.0;
        }
        if let Some(v) = config.timeout_tcp_est {
            ro_data.TIMEOUT_TCP_EST = v.0;
        }

        let mut const_config = einat::EinatConstConfig {
            ro_data,
            prefer_tcx: config.prefer_tcx,
            ..Default::default()
        };

        if let Some(v) = config.frag_track_max_records {
            const_config.frag_track_max_entries = v;
        }
        if let Some(v) = config.binding_max_records {
            // each binding requires 2 records, for both direction
            const_config.binding_max_entries = v * 2;
        }

        const_config.ct_max_entries = if let Some(v) = config.ct_max_records {
            v.min(const_config.binding_max_entries / 2)
        } else {
            const_config.binding_max_entries
        };

        Self(const_config)
    }
}

impl RuntimeConfigEval {
    pub fn try_from(if_config: &ConfigNetIf, defaults: &ConfigDefaults) -> Result<Self> {
        fn unwrap_v4(network: &IpNet) -> Option<Ipv4Net> {
            if let IpNet::V4(network) = network {
                Some(network.trunc())
            } else {
                None
            }
        }

        let v4_internals = if_config
            .snat_internals
            .iter()
            .filter_map(unwrap_v4)
            .collect::<Vec<_>>();

        let v4_no_snat_dests = if_config
            .no_snat_dests
            .iter()
            .filter_map(unwrap_v4)
            .collect::<Vec<_>>();

        #[cfg(feature = "ipv6")]
        fn unwrap_v6(network: &IpNet) -> Option<Ipv6Net> {
            if let IpNet::V6(network) = network {
                Some(network.trunc())
            } else {
                None
            }
        }

        #[cfg(feature = "ipv6")]
        let v6_internals = if_config
            .snat_internals
            .iter()
            .filter_map(unwrap_v6)
            .collect::<Vec<_>>();

        #[cfg(feature = "ipv6")]
        let v6_no_snat_dests = if_config
            .no_snat_dests
            .iter()
            .filter_map(unwrap_v6)
            .collect::<Vec<_>>();

        fn convert_internals<P: Into<IpNet> + IpNetwork>(internals: Vec<P>) -> Vec<ConfigExternal> {
            if internals.is_empty() {
                return Vec::new();
            }

            // add match all config to bypass SNAT
            let mut external =
                ConfigExternal::default_from(P::from(P::Addr::unspecified(), 0).into(), false);
            external.no_snat = true;
            external.no_hairpin = true;

            let mut externals = vec![external];

            for internal in internals {
                if internal.prefix_len() == 0 {
                    // the whole network is internal, return the default empty so SNAT is implicitly performed
                    warn!("specify match all network as internal that clear our other internals");
                    return Vec::new();
                }
                // add more specific internal config to enable SNAT explicitly
                let mut external = ConfigExternal::default_from(internal.into(), false);
                external.is_internal = true;

                externals.push(external);
            }

            externals
        }

        let v4_internals = convert_internals(v4_internals);
        cfg_if::cfg_if!(
            if #[cfg(feature = "ipv6")] {
                let v6_internals = convert_internals(v6_internals);
            } else {
                let v6_internals = Vec::new();
            }
        );

        let mut default_externals = Vec::new();
        if if_config.default_externals {
            if if_config.nat44() {
                default_externals.push(ConfigExternal::match_any_ipv4());
            }
            if if_config.nat66() {
                default_externals.push(ConfigExternal::match_any_ipv6());
            }
        }

        let externals = v4_internals
            .iter()
            .chain(&v6_internals)
            .chain(&if_config.externals)
            .chain(&default_externals)
            .map(|external| External::try_from(external, defaults))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            v4_no_snat_dests,
            #[cfg(feature = "ipv6")]
            v6_no_snat_dests,
            externals,
        })
    }

    pub fn eval(&self, addresses: &IfAddresses) -> RuntimeConfig {
        let v4_addresses = addresses.ipv4.iter().map(|&addr| Ipv4Net::from_addr(addr));
        let v4 = InetConfig::from(&self.v4_no_snat_dests, &self.externals, v4_addresses);

        #[cfg(feature = "ipv6")]
        let v6_addresses = addresses.ipv6.iter().map(|&addr| Ipv6Net::from_addr(addr));
        #[cfg(feature = "ipv6")]
        let v6 = InetConfig::from(&self.v6_no_snat_dests, &self.externals, v6_addresses);

        RuntimeConfig {
            v4,
            #[cfg(feature = "ipv6")]
            v6,
        }
    }
}

impl<P: InetPrefix> InetConfig<P> {
    pub fn hairpin_dests(&self) -> Vec<P> {
        use core::cmp::Ordering;
        let mut res: Vec<_> = self
            .dest_config
            .iter()
            .filter_map(|(prefix, config)| {
                if config.flags.contains(types::DestFlags::HAIRPIN) {
                    Some(*prefix)
                } else {
                    None
                }
            })
            .collect();

        let external = &self.external_addr;
        // move external address to first
        res.sort_by(|a, b| {
            if a == external {
                Ordering::Less
            } else if b == external {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        });

        res
    }

    fn from(
        no_snat_dests: &[P],
        externals: &[External],
        addresses: impl IntoIterator<Item = P>,
    ) -> Self {
        let mut external_addr: Option<P> = None;
        let mut dest_config = PrefixMap::<P, DestConfig>::new();
        let mut external_config = PrefixMap::<P, ExternalConfig>::new();

        for network in no_snat_dests {
            let dest_value = dest_config.entry(*network).or_default();
            dest_value.flags.insert(types::DestFlags::NO_SNAT);
        }

        let mut addresses_set = PrefixSet::from_iter(addresses);
        for external in externals {
            let mut matches = Vec::new();
            match external.address {
                AddressOrMatcher::Static { address } => {
                    if let Some(address) = P::from_ip_addr(address) {
                        if !address.is_unspecified() {
                            matches.push(address);
                        }
                    }
                }
                AddressOrMatcher::Network { network } => {
                    if let Some(network) = P::from_ipnet(network) {
                        if !network.is_unspecified() {
                            matches.push(network);
                        }
                    }
                }
                AddressOrMatcher::Matcher { match_address } => {
                    for address in addresses_set.iter() {
                        if match_address.contains(&address.ip_addr()) && !address.is_unspecified() {
                            matches.push(*address);
                        }
                    }
                }
            }

            for address in matches.iter() {
                addresses_set.remove(address);
            }

            if external_addr.is_none() && !external.no_snat && !external.is_internal {
                for network in matches.iter() {
                    if !network.addr().is_unspecified() {
                        external_addr = Some(*network);
                        break;
                    }
                }
            }

            for network in matches {
                let Entry::Vacant(ext_value) = external_config.entry(network) else {
                    warn!("external config for {} already exists, skipping", network);
                    continue;
                };
                let ext_value = ext_value.default();

                if external.is_internal {
                    ext_value.flags.set(types::ExternalFlags::IS_INTERNAL, true);
                    // configs below are external only and should be inactive for internal
                    continue;
                }

                if !external.no_hairpin {
                    if IpNetwork::prefix_len(&network) == 0 {
                        warn!("a match all network {} with hairpinning is mostly wrong, thus disable hairpinning for it.", &network)
                    } else {
                        let dest_value = dest_config.entry(network).or_default();
                        dest_value
                            .flags
                            .set(types::DestFlags::HAIRPIN, external.no_hairpin);
                    }
                }

                if external.no_snat {
                    ext_value.flags.set(types::ExternalFlags::NO_SNAT, true);
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

        Self {
            external_addr: external_addr.unwrap_or(P::unspecified()),
            dest_config,
            external_config,
        }
    }
}

impl ExternalRanges {
    fn try_from(ranges: &[ProtoRange], allow_zero: bool) -> Result<Self> {
        let ranges: Vec<_> = ranges
            .iter()
            .map(|range| {
                if !allow_zero && *range.inner.start() == 0 {
                    Err(anyhow!("port range {} contains zero, which is not allowed in this type of port range", range))
                } else {
                    Ok(range.inner.clone())
                }
            })
            .collect::<Result<_>>()?;
        let ranges = sort_and_merge_ranges(&ranges);

        if ranges.len() > types::MAX_PORT_RANGES {
            return Err(anyhow!(
                "exceed limit of max {} ranges in port ranges list",
                types::MAX_PORT_RANGES
            ));
        }
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

    fn apply_raw(&self, raw_ranges: &mut types::PortRanges, raw_len: &mut u8) {
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
            is_internal: external.is_internal,
            tcp_ranges,
            udp_ranges,
            icmp_ranges,
            icmp_in_ranges,
            icmp_out_ranges,
        })
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
        if *next.start() > *curr.end() + 1 {
            res.push(core::mem::replace(&mut curr, next.clone()));
        } else if next.end() > curr.end() {
            curr = *curr.start()..=*next.end();
        }
    }
    res.push(curr);

    res
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
        assert_eq!(vec![0..=150, 200..=300], ranges_a.0);
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
