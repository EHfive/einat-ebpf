include!(concat!(env!("OUT_DIR"), "/full_cone_nat.skel.rs"));

use bytemuck::{Pod, Zeroable};

type InetAddr = [u8; 16];

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C, align(4))]
pub struct InetTuple {
    pub src_addr: InetAddr,
    pub dst_addr: InetAddr,
    /// Big-endian
    pub src_port: u16,
    /// Big-endian
    pub dst_port: u16,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct MappingKey {
    pub ext_addr: InetAddr,
    pub dest_addr: InetAddr,
    pub if_index: u32,
    /// Big-endian
    pub ext_port: u16,
    pub is_ipv4: u8,
    pub _pad: u8,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ConnKey {
    pub origin: InetTuple,
    pub mapping_key: MappingKey,
}
