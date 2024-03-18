// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//! User-facing configuration types

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

use anyhow::Result;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use nix::net::if_::if_nametoindex;
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
    Matcher { match_address: AddressMatcher },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigExternal {
    #[serde(flatten)]
    pub address: AddressOrMatcher,
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
    fn match_any(is_ipv4: bool) -> Self {
        let network_any = if is_ipv4 {
            IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap())
        } else {
            IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap())
        };
        Self {
            address: AddressOrMatcher::Matcher {
                match_address: AddressMatcher::Network(network_any),
            },
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
        Self::match_any(true)
    }

    pub fn match_any_ipv6() -> Self {
        Self::match_any(false)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NetIfId {
    Index { if_index: u32 },
    Name { if_name: String },
}

impl Default for NetIfId {
    fn default() -> Self {
        Self::Index { if_index: 0 }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Timeout(pub u64);

#[derive(Debug, Default, Deserialize)]
pub struct ConfigNetIf {
    #[serde(flatten)]
    pub interface: NetIfId,
    #[serde(default)]
    pub nat44: bool,
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
    #[serde(default = "default_true")]
    pub default_externals: bool,
    #[serde(default)]
    pub no_snat_dests: Vec<IpNet>,
    #[serde(default)]
    pub externals: Vec<ConfigExternal>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub defaults: ConfigDefaults,
    #[serde(default)]
    pub interfaces: Vec<ConfigNetIf>,
}

impl NetIfId {
    pub fn resolve_index(&self) -> Result<u32> {
        match self {
            NetIfId::Index { if_index } => Ok(*if_index),
            NetIfId::Name { if_name } => Ok(if_nametoindex(if_name.as_str())?),
        }
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

        deserializer.deserialize_any(RangeVisitor)
    }
}

impl Display for ProtoRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}-{}", self.inner.start(), self.inner.end()))
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
                let Some((start, end)) = v.split_once('-') else {
                    return Err(DeError::custom("missing '-' in port range"));
                };
                let start: u16 = start.parse().map_err(DeError::custom)?;
                let end: u16 = end.parse().map_err(DeError::custom)?;

                if start > end {
                    // empty port range is valid for our bpf program but we explicitly disallow
                    // it on parsing stage to notify user about potential misconfiguration
                    return Err(DeError::custom("empty port range"));
                }

                Ok(ProtoRange {
                    inner: RangeInclusive::new(start, end),
                })
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
if_index = 3

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
