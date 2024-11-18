// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

pub mod types;

#[cfg(feature = "aya")]
pub mod aya;
#[cfg(feature = "libbpf")]
pub mod libbpf;
#[cfg(feature = "libbpf-skel")]
pub mod libbpf_skel;

#[cfg(any(feature = "libbpf", feature = "libbpf-skel"))]
pub mod libbpf_common;

#[cfg(any(feature = "aya", feature = "libbpf"))]
mod obj_data;
#[cfg(any(feature = "aya", feature = "libbpf"))]
use obj_data::einat_obj_data;

use anyhow::Result;
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;

use super::{EbpfHashMapMut, EbpfLpmTrieMut};
use crate::utils::IpNetwork;

pub use types::{
    DestConfig, EinatRoData, ExternalConfig, MapBindingKey, MapBindingValue, MapCtKey, MapCtValue,
};

#[allow(unused)]
#[derive(Debug)]
pub struct EinatConstConfig {
    pub ro_data: types::EinatRoData,
    pub frag_track_max_entries: u32,
    pub binding_max_entries: u32,
    pub ct_max_entries: u32,
    pub prefer_tcx: bool,
}

impl Default for EinatConstConfig {
    fn default() -> Self {
        Self {
            ro_data: Default::default(),
            frag_track_max_entries: 0xffff,
            binding_max_entries: 0xffff * 3,
            ct_max_entries: 0xffff * 3 * 2,
            prefer_tcx: true,
        }
    }
}

/// Model trait for operations on our einat ebpf resources
pub trait EinatEbpf: Sized {
    const NAME: &str;

    type MapBinding: EbpfHashMapMut<MapBindingKey, MapBindingValue>;

    type MapCt: EbpfHashMapMut<MapCtKey, MapCtValue>;

    type Links;

    fn load(config: EinatConstConfig) -> Result<Self>;

    fn map_binding(&self) -> &Self::MapBinding;

    fn map_binding_mut(&mut self) -> &mut Self::MapBinding;

    fn map_ct(&self) -> &Self::MapCt;

    fn map_ct_mut(&mut self) -> &mut Self::MapCt;

    fn with_updating<T, F: FnOnce(&mut Self) -> T>(&mut self, f: F) -> Result<T>;

    fn with_updating_wait<T, F: FnOnce(&mut Self) -> T>(&mut self, f: F) -> Result<T> {
        self.with_updating(|this| {
            // Wait for 1ms and expecting all previous BPF program calls
            // that had not seen g_deleting_map_entries=1 have finished,
            // so binding map and CT map become stable.
            std::thread::sleep(std::time::Duration::from_millis(1));
            f(this)
        })
    }

    fn attach(&mut self, if_name: &str, if_index: u32) -> Result<Self::Links>;

    fn detach(&mut self, links: Self::Links) -> Result<()>;
}

pub trait EinatEbpfInet<P: IpNetwork> {
    type MapExternalConfig: EbpfLpmTrieMut<P, ExternalConfig>;

    type MapDestConfigMap: EbpfLpmTrieMut<P, DestConfig>;

    #[allow(unused)]
    fn external_addr(&self) -> Result<P>;

    fn set_external_addr(&mut self, addr: P) -> Result<()>;

    fn map_external_config(&mut self) -> &mut Self::MapExternalConfig;

    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap;
}

#[cfg(not(feature = "ipv6"))]
pub trait EinatEbpfSkel: EinatEbpf + EinatEbpfInet<Ipv4Net> {}
#[cfg(not(feature = "ipv6"))]
impl<T> EinatEbpfSkel for T where T: EinatEbpf + EinatEbpfInet<Ipv4Net> {}

#[cfg(feature = "ipv6")]
pub trait EinatEbpfSkel: EinatEbpf + EinatEbpfInet<Ipv4Net> + EinatEbpfInet<Ipv6Net> {}
#[cfg(feature = "ipv6")]
impl<T> EinatEbpfSkel for T where T: EinatEbpf + EinatEbpfInet<Ipv4Net> + EinatEbpfInet<Ipv6Net> {}
