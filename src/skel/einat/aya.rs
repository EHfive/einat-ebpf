// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

use std::io;
use std::net::Ipv4Addr;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;

use anyhow::Result;
use aya::maps::{Array, HashMap, LpmTrie, MapData};
use aya::programs::tc::{
    qdisc_add_clsact, qdisc_detach_program, NlOptions, SchedClassifier, SchedClassifierLinkId,
    TcAttachOptions, TcAttachType,
};
use aya::util::KernelVersion;
use aya::{Ebpf, EbpfLoader};
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;

use super::types::{
    self, DestConfig, EinatData, ExternalConfig, MapBindingKey, MapBindingValue, MapCtKey,
    MapCtValue,
};
use super::{einat_obj_data, EinatConstConfig, EinatEbpf, EinatEbpfInet};
use crate::utils::{IpAddress, IpNetwork};

type MapEinatData = Array<MapData, EinatData>;
type MapBinding = HashMap<MapData, MapBindingKey, MapBindingValue>;
type MapCt = HashMap<MapData, MapCtKey, MapCtValue>;
type MapIpv4ExternalConfig = LpmTrie<MapData, <Ipv4Addr as IpAddress>::Data, ExternalConfig>;
type MapIpv4DestConfig = LpmTrie<MapData, <Ipv4Addr as IpAddress>::Data, DestConfig>;
#[cfg(feature = "ipv6")]
type MapIpv6ExternalConfig = LpmTrie<MapData, <Ipv6Addr as IpAddress>::Data, ExternalConfig>;
#[cfg(feature = "ipv6")]
type MapIpv6DestConfig = LpmTrie<MapData, <Ipv6Addr as IpAddress>::Data, DestConfig>;

pub struct EinatAya {
    ebpf: Ebpf,
    map_data: MapEinatData,
    map_binding: MapBinding,
    map_ct: MapCt,
    map_ipv4_dest_config: MapIpv4DestConfig,
    map_ipv4_external_config: MapIpv4ExternalConfig,
    #[cfg(feature = "ipv6")]
    map_ipv6_dest_config: MapIpv6DestConfig,
    #[cfg(feature = "ipv6")]
    map_ipv6_external_config: MapIpv6ExternalConfig,
    use_tcx: bool,
}

pub struct EinatAyaLinks {
    ingress_link_id: SchedClassifierLinkId,
    egress_link_id: SchedClassifierLinkId,
}

fn prog_ingress_assert(ebpf: &mut Ebpf) -> &mut SchedClassifier {
    ebpf.program_mut(types::PROG_INGRESS_REV_SNAT)
        .unwrap()
        .try_into()
        .unwrap()
}

fn prog_egress_assert(ebpf: &mut Ebpf) -> &mut SchedClassifier {
    ebpf.program_mut(types::PROG_EGRESS_SNAT)
        .unwrap()
        .try_into()
        .unwrap()
}

impl EinatAya {
    fn new(mut ebpf: Ebpf, use_tcx: bool) -> Result<Self> {
        let map_data = MapEinatData::try_from(ebpf.take_map(".data").unwrap()).unwrap();

        let map_binding = MapBinding::try_from(ebpf.take_map(types::MAP_BINDING).unwrap()).unwrap();

        let map_ct = MapCt::try_from(ebpf.take_map(types::MAP_CT).unwrap()).unwrap();

        let map_ipv4_dest_config =
            MapIpv4DestConfig::try_from(ebpf.take_map(types::MAP_IPV4_DEST_CONFIG).unwrap())
                .unwrap();

        let map_ipv4_external_config = MapIpv4ExternalConfig::try_from(
            ebpf.take_map(types::MAP_IPV4_EXTERNAL_CONFIG).unwrap(),
        )
        .unwrap();

        #[cfg(feature = "ipv6")]
        let map_ipv6_dest_config =
            MapIpv6DestConfig::try_from(ebpf.take_map(types::MAP_IPV6_DEST_CONFIG).unwrap())
                .unwrap();

        #[cfg(feature = "ipv6")]
        let map_ipv6_external_config = MapIpv6ExternalConfig::try_from(
            ebpf.take_map(types::MAP_IPV6_EXTERNAL_CONFIG).unwrap(),
        )
        .unwrap();

        prog_ingress_assert(&mut ebpf).load()?;
        prog_egress_assert(&mut ebpf).load()?;

        Ok(Self {
            ebpf,
            map_data,
            map_binding,
            map_ct,
            map_ipv4_dest_config,
            map_ipv4_external_config,
            #[cfg(feature = "ipv6")]
            map_ipv6_dest_config,
            #[cfg(feature = "ipv6")]
            map_ipv6_external_config,
            use_tcx,
        })
    }

    fn get_data(&self) -> Result<EinatData> {
        let data = self.map_data.get(&0, 0)?;
        Ok(data)
    }

    fn alter_data_with<T, F: FnOnce(&mut EinatData) -> T>(&mut self, f: F) -> Result<T> {
        let mut data = self.map_data.get(&0, 0)?;
        let r = f(&mut data);
        self.map_data.set(0, data, 0)?;

        Ok(r)
    }
}

impl EinatEbpf for EinatAya {
    const NAME: &str = "Aya";

    type MapBinding = MapBinding;
    type MapCt = MapCt;
    type Links = EinatAyaLinks;

    fn load(config: EinatConstConfig) -> Result<Self> {
        let mut loader = EbpfLoader::new();

        macro_rules! set_global {
            ($($k:ident),*) => {
                $( loader.set_global(stringify!($k), &config.ro_data.$k, true); )*
            };
        }

        set_global!(
            LOG_LEVEL,
            HAS_ETH_ENCAP,
            INGRESS_IPV4,
            EGRESS_IPV4,
            INGRESS_IPV6,
            EGRESS_IPV6,
            ENABLE_FIB_LOOKUP_SRC,
            ALLOW_INBOUND_ICMPX,
            TIMEOUT_FRAGMENT,
            TIMEOUT_PKT_MIN,
            TIMEOUT_PKT_DEFAULT,
            TIMEOUT_TCP_TRANS,
            TIMEOUT_TCP_EST
        );

        loader.set_max_entries(types::MAP_FRAG_TRACK, config.frag_track_max_entries);
        loader.set_max_entries(types::MAP_BINDING, config.binding_max_entries);
        loader.set_max_entries(types::MAP_CT, config.ct_max_entries);

        let use_tcx = config.prefer_tcx
            && KernelVersion::current().is_ok_and(|v| v >= KernelVersion::new(6, 6, 0));

        Self::new(loader.load(einat_obj_data())?, use_tcx)
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

    fn attach(&mut self, if_name: &str, _if_index: u32) -> Result<Self::Links> {
        let (ingress_opt, egress_opt) = if self.use_tcx {
            (
                TcAttachOptions::TcxOrder(Default::default()),
                TcAttachOptions::TcxOrder(Default::default()),
            )
        } else {
            if let Err(e) = qdisc_add_clsact(if_name) {
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
            };

            let _ =
                qdisc_detach_program(if_name, TcAttachType::Ingress, types::PROG_INGRESS_REV_SNAT);
            let _ = qdisc_detach_program(if_name, TcAttachType::Egress, types::PROG_EGRESS_SNAT);

            (
                TcAttachOptions::Netlink(NlOptions {
                    handle: 1,
                    priority: 1,
                }),
                TcAttachOptions::Netlink(NlOptions {
                    handle: 1,
                    priority: 1,
                }),
            )
        };

        let ingress_link_id = prog_ingress_assert(&mut self.ebpf).attach_with_options(
            if_name,
            TcAttachType::Ingress,
            ingress_opt,
        )?;
        let egress_link_id = prog_egress_assert(&mut self.ebpf).attach_with_options(
            if_name,
            TcAttachType::Egress,
            egress_opt,
        );

        let egress_link_id = match egress_link_id {
            Ok(v) => v,
            Err(e) => {
                let _ = prog_ingress_assert(&mut self.ebpf).detach(ingress_link_id);
                return Err(e.into());
            }
        };

        Ok(EinatAyaLinks {
            ingress_link_id,
            egress_link_id,
        })
    }

    fn detach(&mut self, links: Self::Links) -> Result<()> {
        let res = prog_egress_assert(&mut self.ebpf).detach(links.egress_link_id);
        prog_ingress_assert(&mut self.ebpf).detach(links.ingress_link_id)?;

        Ok(res?)
    }
}

impl EinatEbpfInet<Ipv4Net> for EinatAya {
    type MapExternalConfig = MapIpv4ExternalConfig;
    type MapDestConfigMap = MapIpv4DestConfig;

    fn external_addr(&self) -> Result<Ipv4Net> {
        let addr_ne = self.get_data()?.g_ipv4_external_addr;
        let octets: [u8; 4] = bytemuck::bytes_of(&addr_ne).try_into().unwrap();
        Ok(Ipv4Net::from_addr(Ipv4Addr::from(octets)))
    }

    fn set_external_addr(&mut self, addr: Ipv4Net) -> Result<()> {
        self.alter_data_with(|data| {
            data.g_ipv4_external_addr = bytemuck::cast(addr.addr().octets())
        })
    }

    fn map_external_config(&mut self) -> &mut Self::MapExternalConfig {
        &mut self.map_ipv4_external_config
    }

    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv4_dest_config
    }
}

#[cfg(feature = "ipv6")]
impl EinatEbpfInet<Ipv6Net> for EinatAya {
    type MapExternalConfig = MapIpv6ExternalConfig;
    type MapDestConfigMap = MapIpv6DestConfig;

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
