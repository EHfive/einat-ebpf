// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//! User-facing configuration types

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::ops::RangeInclusive;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::de::Error as DeError;
use serde::{de::Visitor, Deserialize};

#[derive(Debug, Clone)]
pub struct ProtoRange {
    pub inner: RangeInclusive<u16>,
}
type ProtoRanges = Vec<ProtoRange>;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ConfigDefaults {
    pub ipv4_local_rule_pref: u32,
    pub ipv6_local_rule_pref: u32,
    pub ipv4_hairpin_rule_pref: u32,
    pub ipv6_hairpin_rule_pref: u32,
    pub ipv4_hairpin_table_id: NonZeroU32,
    pub ipv6_hairpin_table_id: NonZeroU32,
    pub tcp_ranges: ProtoRanges,
    pub udp_ranges: ProtoRanges,
    pub icmp_ranges: ProtoRanges,
    pub icmp_in_ranges: ProtoRanges,
    pub icmp_out_ranges: ProtoRanges,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
pub enum AddressMatcher {
    Range4 { start: Ipv4Addr, end: Ipv4Addr },
    Range6 { start: Ipv6Addr, end: Ipv6Addr },
    Network(IpNet),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
pub enum AddressOrMatcher {
    Static { address: IpAddr },
    Network { network: IpNet },
    Matcher { match_address: AddressMatcher },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigExternal {
    #[serde(flatten)]
    pub address: AddressOrMatcher,
    #[serde(default)]
    pub is_internal: bool,
    #[serde(default)]
    pub no_snat: bool,
    #[serde(default)]
    pub no_hairpin: bool,
    #[serde(default)]
    pub tcp_ranges: Option<ProtoRanges>,
    #[serde(default)]
    pub udp_ranges: Option<ProtoRanges>,
    #[serde(default)]
    pub icmp_ranges: Option<ProtoRanges>,
    #[serde(default)]
    pub icmp_in_ranges: Option<ProtoRanges>,
    #[serde(default)]
    pub icmp_out_ranges: Option<ProtoRanges>,
}

impl ConfigExternal {
    pub fn default_from(network: IpNet, is_matcher: bool) -> Self {
        let address = if is_matcher {
            AddressOrMatcher::Matcher {
                match_address: AddressMatcher::Network(network),
            }
        } else {
            AddressOrMatcher::Network { network }
        };
        Self {
            address,
            is_internal: false,
            no_snat: false,
            no_hairpin: false,
            tcp_ranges: None,
            udp_ranges: None,
            icmp_ranges: None,
            icmp_in_ranges: None,
            icmp_out_ranges: None,
        }
    }

    pub fn match_any_ipv4() -> Self {
        Self::default_from(
            IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            true,
        )
    }

    pub fn match_any_ipv6() -> Self {
        Self::default_from(
            IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()),
            true,
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Timeout(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigHairpinRoute {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub internal_if_names: Vec<String>,
    #[serde(default)]
    pub ip_rule_pref: Option<u32>,
    #[serde(default)]
    pub table_id: Option<NonZeroU32>,
    #[serde(default = "default_ip_protocols")]
    pub ip_protocols: Vec<IpProtocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfLoader {
    Aya,
    Libbpf,
    LibbpfSkel,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigNetIf {
    pub if_name: String,
    #[serde(default)]
    pub nat44: bool,

    #[cfg_attr(not(feature = "ipv6"), allow(dead_code))]
    #[serde(default)]
    pub nat66: bool,

    #[serde(default)]
    pub bpf_log_level: Option<u8>,
    #[serde(default)]
    pub bpf_fib_lookup_external: Option<bool>,
    #[serde(default)]
    pub allow_inbound_icmpx: Option<bool>,
    #[serde(default)]
    pub timeout_fragment: Option<Timeout>,
    #[serde(default)]
    pub timeout_pkt_min: Option<Timeout>,
    #[serde(default)]
    pub timeout_pkt_default: Option<Timeout>,
    #[serde(default)]
    pub timeout_tcp_trans: Option<Timeout>,
    #[serde(default)]
    pub timeout_tcp_est: Option<Timeout>,
    #[serde(default)]
    pub frag_track_max_records: Option<u32>,
    #[serde(default)]
    pub binding_max_records: Option<u32>,
    #[serde(default)]
    pub ct_max_records: Option<u32>,
    #[serde(default = "default_true")]
    pub default_externals: bool,
    #[serde(default)]
    pub snat_internals: Vec<IpNet>,
    #[serde(default)]
    pub no_snat_dests: Vec<IpNet>,
    #[serde(default)]
    pub externals: Vec<ConfigExternal>,
    #[serde(default)]
    pub ipv4_hairpin_route: ConfigHairpinRoute,

    #[cfg_attr(not(feature = "ipv6"), allow(dead_code))]
    #[serde(default)]
    pub ipv6_hairpin_route: ConfigHairpinRoute,

    #[serde(default)]
    pub bpf_loader: Option<BpfLoader>,
    #[serde(default = "default_true")]
    pub prefer_tcx: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub defaults: ConfigDefaults,
    #[serde(default)]
    pub interfaces: Vec<ConfigNetIf>,
}

impl ConfigNetIf {
    pub const fn nat44(&self) -> bool {
        self.nat44
    }

    pub const fn nat66(&self) -> bool {
        cfg!(feature = "ipv6") && self.nat66
    }

    pub const fn nat64(&self) -> bool {
        false
    }
}

impl From<Timeout> for u64 {
    fn from(value: Timeout) -> Self {
        value.0
    }
}

impl From<std::time::Duration> for Timeout {
    fn from(value: std::time::Duration) -> Self {
        Self(value.as_nanos().min(u64::MAX as _) as _)
    }
}

impl<'de> Deserialize<'de> for Timeout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RangeVisitor;
        impl<'de> Visitor<'de> for RangeVisitor {
            type Value = Timeout;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("timeout seconds")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let duration = fundu::parse_duration(v).map_err(DeError::custom)?;

                Ok(duration.into())
            }
        }

        deserializer.deserialize_str(RangeVisitor)
    }
}

impl<'de> Deserialize<'de> for IpProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IpProtocolVisitor;
        impl<'de> Visitor<'de> for IpProtocolVisitor {
            type Value = IpProtocol;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("IP protocol: tcp, udp or icmp")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.eq_ignore_ascii_case("tcp") {
                    Ok(IpProtocol::Tcp)
                } else if v.eq_ignore_ascii_case("udp") {
                    Ok(IpProtocol::Udp)
                } else if v.eq_ignore_ascii_case("icmp") {
                    Ok(IpProtocol::Icmp)
                } else {
                    Err(DeError::custom(
                        "Invalid protocol name, expecting one of \"tcp\", \"udp\" or \"icmp\".",
                    ))
                }
            }
        }

        deserializer.deserialize_str(IpProtocolVisitor)
    }
}

impl FromStr for BpfLoader {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("aya") {
            Ok(BpfLoader::Aya)
        } else if s.eq_ignore_ascii_case("libbpf") {
            Ok(BpfLoader::Libbpf)
        } else if s.eq_ignore_ascii_case("libbpf-skel") {
            Ok(BpfLoader::LibbpfSkel)
        } else {
            Err(anyhow!(
                "Invalid BPF loader, expecting one of \"aya\", \"libbpf\" or \"libbpf-skel\".",
            ))
        }
    }
}

impl<'de> Deserialize<'de> for BpfLoader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BpfLoaderVisitor;
        impl<'de> Visitor<'de> for BpfLoaderVisitor {
            type Value = BpfLoader;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("BPF loader: aya, libbpf or libbpf-skel")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(DeError::custom)
            }
        }

        deserializer.deserialize_str(BpfLoaderVisitor)
    }
}

impl Display for ProtoRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}-{}", self.inner.start(), self.inner.end()))
    }
}

impl FromStr for ProtoRange {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((start, end)) = s.split_once('-') else {
            return Err(anyhow!("missing '-' in port range"));
        };
        let start: u16 = start.parse()?;
        let end: u16 = end.parse()?;

        if start > end {
            // empty port range is valid for our bpf program but we explicitly disallow
            // it on parsing stage to notify user about potential misconfiguration
            return Err(anyhow!("empty port range"));
        }

        Ok(ProtoRange {
            inner: RangeInclusive::new(start, end),
        })
    }
}

impl<'de> Deserialize<'de> for ProtoRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RangeVisitor;
        impl<'de> Visitor<'de> for RangeVisitor {
            type Value = ProtoRange;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("L4 protocol port range")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(DeError::custom)
            }
        }

        deserializer.deserialize_str(RangeVisitor)
    }
}

impl Default for ConfigDefaults {
    fn default() -> Self {
        fn range(inner: RangeInclusive<u16>) -> ProtoRanges {
            debug_assert!(!inner.is_empty());
            vec![ProtoRange { inner }]
        }
        Self {
            ipv4_local_rule_pref: 200,
            ipv6_local_rule_pref: 200,
            ipv4_hairpin_rule_pref: 100,
            ipv6_hairpin_rule_pref: 100,
            ipv4_hairpin_table_id: NonZeroU32::new(4787).unwrap(),
            ipv6_hairpin_table_id: NonZeroU32::new(4787).unwrap(),
            tcp_ranges: range(20000..=29999),
            udp_ranges: range(20000..=29999),
            icmp_ranges: range(0..=u16::MAX),
            icmp_in_ranges: range(0..=9999),
            icmp_out_ranges: range(1000..=u16::MAX),
        }
    }
}

impl AddressMatcher {
    pub fn contains(&self, address: &IpAddr) -> bool {
        match self {
            AddressMatcher::Network(network) => match network {
                IpNet::V4(network) => match address {
                    IpAddr::V4(v4) => network.contains(&Ipv4Net::new(*v4, 32).unwrap()),
                    _ => false,
                },
                IpNet::V6(network) => match address {
                    IpAddr::V6(v6) => network.contains(&Ipv6Net::new(*v6, 128).unwrap()),
                    _ => false,
                },
            },
            AddressMatcher::Range4 { start, end } => match address {
                IpAddr::V4(v4) => v4 >= start && v4 <= end,
                _ => false,
            },
            AddressMatcher::Range6 { start, end } => match address {
                IpAddr::V6(v6) => v6 >= start && v6 <= end,
                _ => false,
            },
        }
    }
}

const fn default_true() -> bool {
    true
}

fn default_ip_protocols() -> Vec<IpProtocol> {
    vec![IpProtocol::Tcp, IpProtocol::Udp]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let config_str = r#"
[defaults]
tcp_ranges = ["10000-65535"]
udp_ranges = ["10000-65535"]
icmp_ranges = ["0-65535"]
icmp_in_ranges = ["0-9999"]
icmp_out_ranges = ["1000-65535"]

[[interfaces]]
if_name = "eth0"
nat44 = true
nat66 = false
bpf_fib_lookup_external = false
default_externals = true
no_snat_dests = ["192.168.0.0/16"]
hairpin_dests = ["192.168.2.0/24"]

[[interfaces.externals]]
address = "192.168.1.1"
no_snat = false
no_hairpin = false
tcp_ranges = ["10000-65535"]
udp_ranges = ["10000-65535"]
icmp_ranges = ["0-65535"]
icmp_in_ranges = ["0-9999"]
icmp_out_ranges = ["1000-65535"]

[[interfaces.externals]]
match_address = "192.168.1.1/24"

[[interfaces.externals]]
match_address = { start = "192.168.1.1", end = "192.168.1.255" }
        "#;
        let _config: Config = toml::from_str(config_str).unwrap();
    }
}
