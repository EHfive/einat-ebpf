include!(concat!(env!("OUT_DIR"), "/full_cone_nat.skel.rs"));

use bytemuck::{Pod, Zeroable};

type InetAddr = [u8; 16];

#[derive(Clone, Copy, Debug, Default, Zeroable, Pod)]
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

#[derive(Clone, Copy, Debug, Default, Zeroable, Pod)]
#[repr(C)]
pub struct Ipv6LpmKey {
    pub prefix_len: u32,
    pub ip: [u8; 16],
}

#[derive(Clone, Copy, Debug, Default, Zeroable, Pod)]
#[repr(C)]
pub struct PortRange {
    pub from_port: u16,
    pub to_port: u16,
}

const MAX_PORT_RANGES: usize = 4;

#[derive(Clone, Copy, Debug, Default, Zeroable, Pod)]
#[repr(C)]
pub struct ExternalConfig {
    pub tcp_range: [PortRange; MAX_PORT_RANGES],
    pub udp_range: [PortRange; MAX_PORT_RANGES],
    pub icmp_range: [PortRange; MAX_PORT_RANGES],
    pub tcp_range_len: u8,
    pub udp_range_len: u8,
    pub icmp_range_len: u8,
    pub flags: u8,
}

#[derive(Clone, Copy, Debug, Default, Zeroable, Pod)]
#[repr(C)]
pub struct DestConfig {
    pub flags: u8,
}
