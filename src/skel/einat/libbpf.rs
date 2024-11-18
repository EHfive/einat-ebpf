// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

use std::net::Ipv4Addr;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;

use anyhow::Result;
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use libbpf_rs::{MapCore, MapFlags, MapHandle, Object};

use super::super::libbpf::LibbpfMap;
use super::types::{self, EinatData};
use super::{einat_obj_data, EinatConstConfig, EinatEbpf, EinatEbpfInet};
use crate::utils::IpNetwork;

use super::libbpf_common::{attach, detach, EinatLibbpfLinks};

type Map = LibbpfMap<MapHandle>;

pub struct EinatLibbpf {
    obj: Object,
    map_data: MapHandle,
    map_binding: Map,
    map_ct: Map,
    map_ipv4_dest_config: Map,
    map_ipv4_external_config: Map,
    #[cfg(feature = "ipv6")]
    map_ipv6_dest_config: Map,
    #[cfg(feature = "ipv6")]
    map_ipv6_external_config: Map,
}

unsafe impl Send for EinatLibbpf {}
unsafe impl Sync for EinatLibbpf {}

impl EinatLibbpf {
    // XXX: mmap data map instead?
    fn get_data(&self) -> Result<EinatData> {
        let data = self
            .map_data
            .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?
            .unwrap();
        Ok(*bytemuck::from_bytes(&data))
    }

    fn alter_data_with<T, F: FnOnce(&mut EinatData) -> T>(&mut self, f: F) -> Result<T> {
        let mut data_raw = self
            .map_data
            .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?
            .unwrap();
        let data: &mut EinatData = bytemuck::from_bytes_mut(&mut data_raw);

        let r = f(data);

        self.map_data
            .update(&0u32.to_ne_bytes(), &data_raw, MapFlags::ANY)?;
        Ok(r)
    }
}

impl EinatEbpf for EinatLibbpf {
    type MapBinding = Map;
    type MapCt = Map;
    type Links = EinatLibbpfLinks;

    fn load(config: EinatConstConfig) -> Result<Self> {
        let mut open_obj = libbpf_rs::ObjectBuilder::default()
            .name("einat")
            .expect("failed to name obj as einat")
            .debug(false)
            .open_memory(einat_obj_data())?;

        let mut map_ro_data = None;
        let mut map_frag_track = None;
        let mut map_binding = None;
        let mut map_ct = None;

        for map in open_obj.maps_mut() {
            match map.name().to_string_lossy().as_ref() {
                "einat.rodata" => map_ro_data = Some(map),
                types::MAP_FRAG_TRACK => map_frag_track = Some(map),
                types::MAP_BINDING => map_binding = Some(map),
                types::MAP_CT => map_ct = Some(map),
                _ => (),
            }
        }

        let ro_data_bytes = bytemuck::bytes_of(&config.ro_data);

        let mut map_ro_data = map_ro_data.expect("failed to get rodata map");
        let initial_value = map_ro_data.initial_value_mut().expect("rodata not mmaped");
        let initial_value = &mut initial_value[..ro_data_bytes.len()];

        initial_value.copy_from_slice(ro_data_bytes);

        // set max_entries

        map_frag_track
            .unwrap()
            .set_max_entries(config.frag_track_max_entries)?;
        map_binding
            .unwrap()
            .set_max_entries(config.binding_max_entries)?;
        map_ct.unwrap().set_max_entries(config.ct_max_entries)?;

        let obj = open_obj.load()?;

        // retrieve maps

        let mut map_data = None;
        let mut map_binding = None;
        let mut map_ct = None;
        let mut map_ipv4_dest_config = None;
        let mut map_ipv4_external_config = None;
        #[cfg(feature = "ipv6")]
        let mut map_ipv6_dest_config = None;
        #[cfg(feature = "ipv6")]
        let mut map_ipv6_external_config = None;

        for map in obj.maps() {
            match map.name().to_string_lossy().as_ref() {
                "einat.data" => map_data = Some(map),
                types::MAP_BINDING => map_binding = Some(map),
                types::MAP_CT => map_ct = Some(map),
                types::MAP_IPV4_DEST_CONFIG => map_ipv4_dest_config = Some(map),
                types::MAP_IPV4_EXTERNAL_CONFIG => map_ipv4_external_config = Some(map),
                #[cfg(feature = "ipv6")]
                types::MAP_IPV6_DEST_CONFIG => map_ipv6_dest_config = Some(map),
                #[cfg(feature = "ipv6")]
                types::MAP_IPV6_EXTERNAL_CONFIG => map_ipv6_external_config = Some(map),
                _ => (),
            }
        }

        macro_rules! wrap {
            ($n:ident) => {
                LibbpfMap(MapHandle::try_from(&$n.unwrap())?)
            };
        }

        Ok(Self {
            map_data: MapHandle::try_from(&map_data.unwrap())?,
            map_binding: wrap!(map_binding),
            map_ct: wrap!(map_ct),
            map_ipv4_dest_config: wrap!(map_ipv4_dest_config),
            map_ipv4_external_config: wrap!(map_ipv4_external_config),
            #[cfg(feature = "ipv6")]
            map_ipv6_dest_config: wrap!(map_ipv6_dest_config),
            #[cfg(feature = "ipv6")]
            map_ipv6_external_config: wrap!(map_ipv6_external_config),
            obj,
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
        self.alter_data_with(|data| data.g_deleting_map_entries = 1)?;
        let r = f(self);
        self.alter_data_with(|data| data.g_deleting_map_entries = 0)?;
        Ok(r)
    }

    fn attach(&mut self, _if_name: &str, if_index: u32) -> Result<Self::Links> {
        let mut prog_ingress = None;
        let mut prog_egress = None;

        for prog in self.obj.progs() {
            match prog.name().to_string_lossy().as_ref() {
                types::PROG_INGRESS_REV_SNAT => prog_ingress = Some(prog),
                types::PROG_EGRESS_SNAT => prog_egress = Some(prog),
                _ => unreachable!(),
            }
        }

        attach(&prog_ingress.unwrap(), &prog_egress.unwrap(), if_index)
    }

    fn detach(&mut self, links: Self::Links) -> Result<()> {
        detach(links)
    }
}

impl EinatEbpfInet<Ipv4Net> for EinatLibbpf {
    type MapExternalConfig = Map;

    type MapDestConfigMap = Map;

    fn external_addr(&self) -> Result<Ipv4Net> {
        let addr_ne = self.get_data()?.g_ipv4_external_addr;
        let octets: [u8; 4] = bytemuck::bytes_of(&addr_ne).try_into().unwrap();
        Ok(Ipv4Net::from_addr(Ipv4Addr::from(octets)))
    }

    fn set_external_addr(&mut self, addr: Ipv4Net) -> Result<()> {
        let addr_be: u32 = bytemuck::cast(addr.addr().octets());
        self.alter_data_with(|data| data.g_ipv4_external_addr = addr_be)
    }

    fn map_external_config(&mut self) -> &mut Self::MapExternalConfig {
        &mut self.map_ipv4_external_config
    }

    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv4_dest_config
    }
}

#[cfg(feature = "ipv6")]
impl EinatEbpfInet<Ipv6Net> for EinatLibbpf {
    type MapExternalConfig = Map;

    type MapDestConfigMap = Map;

    fn external_addr(&self) -> Result<Ipv6Net> {
        let addr_ne = self.get_data()?.g_ipv6_external_addr;
        let octets: [u8; 16] = bytemuck::bytes_of(&addr_ne).try_into().unwrap();
        Ok(Ipv6Net::from_addr(Ipv6Addr::from(octets)))
    }

    fn set_external_addr(&mut self, addr: Ipv6Net) -> Result<()> {
        self.alter_data_with(|data| {
            data.g_ipv6_external_addr = bytemuck::cast(addr.addr().octets())
        })
    }

    fn map_external_config(&mut self) -> &mut Self::MapExternalConfig {
        &mut self.map_ipv6_external_config
    }

    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv6_dest_config
    }
}
