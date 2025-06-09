// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

mod skel_build {
    include!(concat!(env!("OUT_DIR"), "/einat.skel.rs"));
}
use skel_build::types as einat_types;
use skel_build::*;

use std::mem;
use std::net::Ipv4Addr;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;

use anyhow::Result;
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapHandle, OpenObject};
use self_cell::{self_cell, MutBorrow};

use super::super::libbpf::LibbpfMap;
use super::{EinatConstConfig, EinatEbpf, EinatEbpfInet, EinatRoData};
use crate::utils::IpNetwork;

use super::libbpf_common::{attach, detach, EinatLibbpfLinks};

self_cell!(
    struct OwnedSkel {
        owner: MutBorrow<mem::MaybeUninit<OpenObject>>,

        #[covariant]
        dependent: EinatSkel,
    }
);

type Map = LibbpfMap<MapHandle>;

pub struct EinatLibbpfSkel {
    skel: OwnedSkel,
    map_binding: Map,
    map_ct: Map,
    map_ipv4_dest_config: Map,
    map_ipv4_external_config: Map,
    #[cfg(feature = "ipv6")]
    map_ipv6_dest_config: Map,
    #[cfg(feature = "ipv6")]
    map_ipv6_external_config: Map,
}

unsafe impl Send for EinatLibbpfSkel {}
unsafe impl Sync for EinatLibbpfSkel {}

impl EinatEbpf for EinatLibbpfSkel {
    const NAME: &'static str = "libbpf skeleton";

    type MapBinding = Map;
    type MapCt = Map;
    type Links = EinatLibbpfLinks;

    fn load(config: EinatConstConfig) -> Result<Self> {
        let obj = MutBorrow::new(mem::MaybeUninit::zeroed());

        let skel = OwnedSkel::try_new(obj, |obj| -> Result<_> {
            let mut open_skel = EinatSkelBuilder::default().open(obj.borrow_mut())?;
            open_skel
                .maps
                .rodata_data
                .as_mut()
                .map(|data| {
                    **data = unsafe {
                        mem::transmute::<EinatRoData, einat_types::rodata>(config.ro_data)
                    }
                })
                .unwrap();

            open_skel
                .maps
                .map_frag_track
                .set_max_entries(config.frag_track_max_entries)?;
            open_skel
                .maps
                .map_binding
                .set_max_entries(config.binding_max_entries)?;
            open_skel
                .maps
                .map_ct
                .set_max_entries(config.ct_max_entries)?;

            Ok(open_skel.load()?)
        })?;

        let maps = &skel.borrow_dependent().maps;

        macro_rules! wrap {
            ($n:ident) => {
                LibbpfMap(MapHandle::try_from(&maps.$n)?)
            };
        }

        Ok(Self {
            map_binding: wrap!(map_binding),
            map_ct: wrap!(map_ct),
            map_ipv4_dest_config: wrap!(map_ipv4_dest_config),
            map_ipv4_external_config: wrap!(map_ipv4_external_config),
            #[cfg(feature = "ipv6")]
            map_ipv6_dest_config: wrap!(map_ipv6_dest_config),
            #[cfg(feature = "ipv6")]
            map_ipv6_external_config: wrap!(map_ipv6_external_config),
            skel,
        })
    }

    fn map_binding(&self) -> &Self::MapBinding {
        &self.map_binding
    }

    fn map_binding_mut(&mut self) -> &mut Self::MapBinding {
        &mut self.map_binding
    }

    fn map_ct(&self) -> &Self::MapCt {
        &self.map_ct
    }

    fn map_ct_mut(&mut self) -> &mut Self::MapCt {
        &mut self.map_ct
    }

    fn with_updating<T, F: FnOnce(&mut Self) -> T>(&mut self, f: F) -> Result<T> {
        self.skel.with_dependent_mut(|_, skel| {
            skel.maps
                .data_data
                .as_mut()
                .map(|data| data.g_deleting_map_entries = 1)
                .unwrap();
        });
        let r = f(self);
        self.skel.with_dependent_mut(|_, skel| {
            skel.maps
                .data_data
                .as_mut()
                .map(|data| data.g_deleting_map_entries = 0)
                .unwrap();
        });
        Ok(r)
    }

    fn attach(&mut self, _if_name: &str, if_index: u32) -> Result<Self::Links> {
        attach(
            &self.skel.borrow_dependent().progs.ingress_rev_snat,
            &self.skel.borrow_dependent().progs.egress_snat,
            if_index,
        )
    }

    fn detach(&mut self, links: Self::Links) -> Result<()> {
        detach(links)
    }
}

impl EinatEbpfInet<Ipv4Net> for EinatLibbpfSkel {
    type MapExternalConfig = Map;

    type MapDestConfigMap = Map;

    fn external_addr(&self) -> Result<Ipv4Net> {
        let addr = self
            .skel
            .borrow_dependent()
            .maps
            .data_data
            .as_ref()
            .map_or(Default::default(), |data| data.g_ipv4_external_addr);
        let octets: [u8; 4] = bytemuck::bytes_of(&addr).try_into().unwrap();
        Ok(Ipv4Net::from_addr(Ipv4Addr::from(octets)))
    }

    fn set_external_addr(&mut self, addr: Ipv4Net) -> Result<()> {
        self.skel.with_dependent_mut(|_, skel| {
            skel.maps
                .data_data
                .as_mut()
                .map(|data| data.g_ipv4_external_addr = bytemuck::cast(addr.addr().octets()))
                .unwrap();
        });
        Ok(())
    }

    fn map_external_config(&mut self) -> &mut Self::MapExternalConfig {
        &mut self.map_ipv4_external_config
    }

    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv4_dest_config
    }
}

#[cfg(feature = "ipv6")]
impl EinatEbpfInet<Ipv6Net> for EinatLibbpfSkel {
    type MapExternalConfig = Map;

    type MapDestConfigMap = Map;

    fn external_addr(&self) -> Result<Ipv6Net> {
        let addr = self
            .skel
            .borrow_dependent()
            .maps
            .data_data
            .as_ref()
            .map_or(Default::default(), |data| data.g_ipv6_external_addr);
        let octets: [u8; 16] = bytemuck::bytes_of(&addr).try_into().unwrap();
        Ok(Ipv6Net::from_addr(Ipv6Addr::from(octets)))
    }

    fn set_external_addr(&mut self, addr: Ipv6Net) -> Result<()> {
        self.skel.with_dependent_mut(|_, skel| {
            skel.maps
                .data_data
                .as_mut()
                .map(|data| data.g_ipv6_external_addr = bytemuck::cast(addr.addr().octets()))
                .unwrap();
        });
        Ok(())
    }

    fn map_external_config(&mut self) -> &mut Self::MapExternalConfig {
        &mut self.map_ipv6_external_config
    }

    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv6_dest_config
    }
}
