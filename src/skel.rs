// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
include!(concat!(env!("OUT_DIR"), "/einat.skel.rs"));

#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
#[repr(transparent)]
pub struct InetAddr {
    #[cfg(feature = "ipv6")]
    pub inner: [u8; 16],
    #[cfg(not(feature = "ipv6"))]
    pub inner: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
#[repr(C, align(4))]
pub struct InetTuple {
    pub src_addr: InetAddr,
    pub dst_addr: InetAddr,
    /// Big-endian
    pub src_port: u16,
    /// Big-endian
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug, Default, Zeroable, Pod)]
#[repr(C)]
pub struct Ipv4LpmKey {
    pub prefix_len: u32,
    pub ip: [u8; 4],
}

#[cfg(feature = "ipv6")]
#[derive(Clone, Copy, Debug, Default, Zeroable, Pod)]
#[repr(C)]
pub struct Ipv6LpmKey {
    pub prefix_len: u32,
    pub ip: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
#[repr(C)]
pub struct PortRange {
    pub start_port: u16,
    pub end_port: u16,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct ExternalFlags: u8 {
        const NO_SNAT = 0b10;
    }
}

pub const MAX_PORT_RANGES: usize = 4;

pub type PortRanges = [PortRange; MAX_PORT_RANGES];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
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

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct DestFlags: u8 {
        const HAIRPIN = 0b01;
        const NO_SNAT = 0b10;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
#[repr(C)]
pub struct DestConfig {
    pub flags: DestFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct BindingFlags: u8 {
        const ORIG_DIR = 0b001;
        const ADDR_IPV4 = 0b010;
        const ADDR_IPV6 = 0b100;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
#[repr(C)]
pub struct MapBindingKey {
    pub if_index: u32,
    pub flags: BindingFlags,
    pub l4proto: u8,
    pub from_port: u16,
    pub from_addr: InetAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
#[repr(C)]
pub struct MapCtKey {
    pub if_index: u32,
    pub flags: BindingFlags,
    pub l4proto: u8,
    pub _pad: u16,
    pub external: InetTuple,
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
