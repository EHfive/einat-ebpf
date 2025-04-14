// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#![allow(dead_code)]

use std::fmt::Debug;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;

use crate::derive_pod;
use crate::utils::IpAddress;

pub const MAP_FRAG_TRACK: &str = "map_frag_track";
pub const MAP_BINDING: &str = "map_binding";
pub const MAP_CT: &str = "map_ct";
pub const MAP_IPV4_EXTERNAL_CONFIG: &str = "map_ipv4_external_config";
pub const MAP_IPV4_DEST_CONFIG: &str = "map_ipv4_dest_config";
#[cfg(feature = "ipv6")]
pub const MAP_IPV6_EXTERNAL_CONFIG: &str = "map_ipv6_external_config";
#[cfg(feature = "ipv6")]
pub const MAP_IPV6_DEST_CONFIG: &str = "map_ipv6_dest_config";

pub const PROG_INGRESS_REV_SNAT: &str = "ingress_rev_snat";
pub const PROG_EGRESS_SNAT: &str = "egress_snat";

#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroable, Pod)]
#[repr(C)]
pub struct EinatRoData {
    pub LOG_LEVEL: u8,
    pub HAS_ETH_ENCAP: u8,
    pub INGRESS_IPV4: u8,
    pub EGRESS_IPV4: u8,
    pub INGRESS_IPV6: u8,
    pub EGRESS_IPV6: u8,
    pub ENABLE_FIB_LOOKUP_SRC: u8,
    pub ALLOW_INBOUND_ICMPX: u8,
    pub TIMEOUT_FRAGMENT: u64,
    pub TIMEOUT_PKT_MIN: u64,
    pub TIMEOUT_PKT_DEFAULT: u64,
    pub TIMEOUT_TCP_TRANS: u64,
    pub TIMEOUT_TCP_EST: u64,
}

impl Default for EinatRoData {
    fn default() -> Self {
        const E9: u64 = 1_000_000_000;
        Self {
            LOG_LEVEL: 0,
            HAS_ETH_ENCAP: 1,
            INGRESS_IPV4: 1,
            EGRESS_IPV4: 1,
            INGRESS_IPV6: 1,
            EGRESS_IPV6: 1,
            ENABLE_FIB_LOOKUP_SRC: 0,
            ALLOW_INBOUND_ICMPX: 1,
            TIMEOUT_FRAGMENT: 2 * E9,
            TIMEOUT_PKT_MIN: 120 * E9,
            TIMEOUT_PKT_DEFAULT: 300 * E9,
            TIMEOUT_TCP_TRANS: 240 * E9,
            TIMEOUT_TCP_EST: 7440 * E9,
        }
    }
}

derive_pod!(
    #[repr(C, packed)]
    pub struct EinatData {
        pub g_ipv4_external_addr: u32,
        #[cfg(feature = "ipv6")]
        pub g_ipv6_external_addr: [u32; 4],
        pub g_deleting_map_entries: u8,
    }
);

derive_pod!(
    #[repr(transparent)]
    pub struct InetAddr {
        #[cfg(feature = "ipv6")]
        pub inner: [u8; 16],
        #[cfg(not(feature = "ipv6"))]
        pub inner: [u8; 4],
    }
);
derive_pod!(
    #[repr(C, align(4))]
    pub struct InetTuple {
        pub src_addr: InetAddr,
        pub dst_addr: InetAddr,
        /// Big-endian
        pub src_port: u16,
        /// Big-endian
        pub dst_port: u16,
    }
);

derive_pod!(
    #[repr(C)]
    pub struct Ipv4LpmKey {
        pub prefix_len: u32,
        pub ip: [u8; 4],
    }
);

#[cfg(feature = "ipv6")]
derive_pod!(
    #[repr(C)]
    pub struct Ipv6LpmKey {
        pub prefix_len: u32,
        pub ip: [u8; 16],
    }
);

derive_pod!(
    #[repr(C)]
    pub struct PortRange {
        pub start_port: u16,
        pub end_port: u16,
    }
);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct ExternalFlags: u8 {
        const IS_INTERNAL = 0b1;
        const NO_SNAT = 0b10;
    }
}

pub const MAX_PORT_RANGES: usize = 4;

pub type PortRanges = [PortRange; MAX_PORT_RANGES];

derive_pod!(
    #[repr(C)]
    pub struct ExternalConfig {
        pub tcp_range: PortRanges,
        pub udp_range: PortRanges,
        pub icmp_range: PortRanges,
        pub icmp_in_range: PortRanges,
        pub icmp_out_range: PortRanges,
        pub tcp_range_len: u8,
        pub udp_range_len: u8,
        pub icmp_range_len: u8,
        pub icmp_in_range_len: u8,
        pub icmp_out_range_len: u8,
        pub flags: ExternalFlags,
    }
);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct DestFlags: u8 {
        const HAIRPIN = 0b01;
        const NO_SNAT = 0b10;
    }
}

derive_pod!(
    #[repr(C)]
    pub struct DestConfig {
        pub flags: DestFlags,
    }
);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct BindingFlags: u8 {
        const ORIG_DIR = 0b001;
        const ADDR_IPV4 = 0b010;
        const ADDR_IPV6 = 0b100;
    }
}
derive_pod!(
    #[repr(C)]
    pub struct MapBindingKey {
        pub if_index: u32,
        pub flags: BindingFlags,
        pub l4proto: u8,
        pub from_port: u16,
        pub from_addr: InetAddr,
    }
);
derive_pod!(
    #[repr(C)]
    pub struct MapBindingValue {
        pub to_addr: InetAddr,
        pub to_port: u16,
        pub flags: BindingFlags,
        pub is_static: u8,
        pub use_: u32,
        pub ref_: u32,
        pub seq: u32,
    }
);

derive_pod!(
    #[repr(C)]
    pub struct MapCtKey {
        pub if_index: u32,
        pub flags: BindingFlags,
        pub l4proto: u8,
        pub _pad: u16,
        pub external: InetTuple,
    }
);

derive_pod!(
    #[repr(C)]
    pub struct MapCtValue {
        pub origin: InetTuple,
        pub flags: u8,
        pub _pad: [u8; 3],
        pub state: u32,
        pub seq: u32,
        pub bpf_timer: [u64; 2],
    }
);

pub fn ip_address_from_inet_addr<'a, P: IpAddress>(addr: &'a InetAddr) -> P
where
    P::Data: TryFrom<&'a [u8], Error: Debug>,
{
    P::from_data((&(addr.inner[..(P::LEN as usize) / 8])).try_into().unwrap())
}

impl From<Ipv4Addr> for InetAddr {
    #[cfg(feature = "ipv6")]
    fn from(value: Ipv4Addr) -> Self {
        let mut res = Self::default();
        let octets = value.octets();
        res.inner[..octets.len()].copy_from_slice(&octets);
        res
    }
    #[cfg(not(feature = "ipv6"))]
    fn from(value: Ipv4Addr) -> Self {
        Self {
            inner: value.octets(),
        }
    }
}

#[cfg(feature = "ipv6")]
impl From<Ipv6Addr> for InetAddr {
    fn from(value: Ipv6Addr) -> Self {
        Self {
            inner: value.octets(),
        }
    }
}

impl From<IpAddr> for InetAddr {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => v4.into(),
            #[cfg(feature = "ipv6")]
            IpAddr::V6(v6) => v6.into(),
            #[cfg(not(feature = "ipv6"))]
            IpAddr::V6(_) => {
                panic!("unexpected")
            }
        }
    }
}

impl From<Ipv4Net> for Ipv4LpmKey {
    fn from(value: Ipv4Net) -> Self {
        Self {
            ip: value.addr().octets(),
            prefix_len: value.prefix_len() as _,
        }
    }
}

#[cfg(feature = "ipv6")]
impl From<Ipv6Net> for Ipv6LpmKey {
    fn from(value: Ipv6Net) -> Self {
        Self {
            ip: value.addr().octets(),
            prefix_len: value.prefix_len() as _,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_addr_to_ip_addr() {
        let inet_addr = InetAddr {
            #[cfg(feature = "ipv6")]
            inner: [192, 168, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            #[cfg(not(feature = "ipv6"))]
            inner: [192, 168, 0, 1],
        };

        assert_eq!(
            Ipv4Addr::new(192, 168, 0, 1),
            ip_address_from_inet_addr::<Ipv4Addr>(&inet_addr)
        );

        #[cfg(feature = "ipv6")]
        assert_eq!(
            Ipv6Addr::new(0xc0a8, 1, 0, 0, 0, 0, 0, 0xffff),
            ip_address_from_inet_addr::<Ipv6Addr>(&inet_addr)
        );
    }
}
