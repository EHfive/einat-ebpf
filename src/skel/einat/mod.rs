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
    const NAME: &'static str;

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

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;
    use std::collections::HashSet;
    use std::fmt::Debug;
    use std::hash::RandomState;
    use std::net;

    use super::*;
    use crate::skel::{EbpfHashMap, EbpfLpmTrie, EbpfMapFlags};
    use crate::utils::IpAddress;

    #[cfg(feature = "aya")]
    #[test]
    #[ignore = "bpf"]
    fn test_aya_maps() {
        test_skel_maps::<aya::EinatAya>();
        test_skel_inet_maps::<Ipv4Net, aya::EinatAya>();
        #[cfg(feature = "ipv6")]
        test_skel_inet_maps::<Ipv6Net, aya::EinatAya>();

        test_skel_attach::<aya::EinatAya>();
    }

    #[cfg(feature = "libbpf")]
    #[test]
    #[ignore = "bpf"]
    fn test_libbpf_maps() {
        test_skel_maps::<libbpf::EinatLibbpf>();
        test_skel_inet_maps::<Ipv4Net, libbpf::EinatLibbpf>();
        #[cfg(feature = "ipv6")]
        test_skel_inet_maps::<Ipv6Net, libbpf::EinatLibbpf>();

        test_skel_attach::<libbpf::EinatLibbpf>();
    }

    #[cfg(feature = "libbpf-skel")]
    #[test]
    #[ignore = "bpf"]
    fn test_libbpf_skel_maps() {
        test_skel_maps::<libbpf_skel::EinatLibbpfSkel>();
        test_skel_inet_maps::<Ipv4Net, libbpf_skel::EinatLibbpfSkel>();
        #[cfg(feature = "ipv6")]
        test_skel_inet_maps::<Ipv6Net, libbpf_skel::EinatLibbpfSkel>();

        test_skel_attach::<libbpf_skel::EinatLibbpfSkel>();
    }

    fn test_skel_attach<T: EinatEbpf>() {
        let mut skel = T::load(EinatConstConfig::default()).unwrap();
        let links = skel.attach("lo", 1).unwrap();
        skel.detach(links).unwrap();
    }

    // test if key and value struct size matches BTF map and general map operations
    fn test_skel_maps<T: EinatEbpf>() {
        let mut skel = T::load(EinatConstConfig::default()).unwrap();

        skel.with_updating_wait(|_| {}).unwrap();

        macro_rules! test_map {
            ($map:ident, $kt:tt) => {{
                let mut keys: Vec<_> = (0..100)
                    .map(|i| $kt {
                        if_index: i,
                        ..Default::default()
                    })
                    .collect();

                for k in keys.iter() {
                    skel.$map()
                        .update(k, &Default::default(), EbpfMapFlags::NO_EXIST)
                        .unwrap();
                }

                let mut keys_set = HashSet::<_, RandomState>::from_iter(keys.iter());
                for k in skel.$map().keys() {
                    let k = k.unwrap();
                    assert!(keys_set.remove(k.borrow()));
                }

                let key = keys.pop().unwrap();

                assert!(skel
                    .$map()
                    .lookup(&key, EbpfMapFlags::ANY)
                    .unwrap()
                    .is_some());

                skel.$map().delete(&key).unwrap();

                assert!(skel
                    .$map()
                    .lookup(&key, EbpfMapFlags::ANY)
                    .unwrap()
                    .is_none());

                skel.$map().delete_batch(&keys, EbpfMapFlags::ANY).unwrap();

                for k in keys.iter() {
                    assert!(skel.$map().lookup(k, EbpfMapFlags::ANY).unwrap().is_none());
                }
            }};
        }

        test_map!(map_binding_mut, MapBindingKey);
        test_map!(map_ct_mut, MapCtKey);
    }

    trait InetKeyGen: Sized + IpAddress {
        fn gen_idx(i: u32) -> Self {
            Self::gen_idx_len(i, Self::LEN)
        }

        fn gen_idx_len(i: u32, len: u8) -> Self;
    }

    impl InetKeyGen for Ipv4Net {
        fn gen_idx_len(i: u32, len: u8) -> Self {
            IpNetwork::from(net::Ipv4Addr::from_bits(i as _), len)
        }
    }

    #[cfg(feature = "ipv6")]
    impl InetKeyGen for Ipv6Net {
        fn gen_idx_len(i: u32, len: u8) -> Self {
            IpNetwork::from(net::Ipv6Addr::from_bits(i as _), len)
        }
    }

    fn test_skel_inet_maps<
        P: IpNetwork + InetKeyGen + Eq + Debug + Copy,
        T: EinatEbpf + EinatEbpfInet<P>,
    >() {
        let mut skel = T::load(EinatConstConfig::default()).unwrap();
        let addr = P::gen_idx(1);
        skel.set_external_addr(addr).unwrap();
        assert_eq!(addr, skel.external_addr().unwrap());

        macro_rules! test_map {
            ($map:ident) => {{
                let keys: Vec<_> = (0..P::LEN).map(|i| P::gen_idx_len(i as _, i)).collect();
                for k in keys.iter() {
                    skel.$map()
                        .update(k, &Default::default(), EbpfMapFlags::NO_EXIST)
                        .unwrap();
                }

                for k in keys.iter() {
                    assert!(skel.$map().lookup(k, EbpfMapFlags::ANY).unwrap().is_some());
                }

                for k in keys.iter() {
                    skel.$map().delete(k).unwrap();
                }

                for k in keys.iter() {
                    assert!(skel.$map().lookup(k, EbpfMapFlags::ANY).unwrap().is_none());
                }
            }};
        }

        test_map!(map_external_config);
        test_map!(map_dest_config);
    }
}
