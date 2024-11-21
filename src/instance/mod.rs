// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

mod config;
pub use config::*;

use std::borrow::Borrow;
use std::net::Ipv4Addr;
use std::time::Instant;

use anyhow::{anyhow, Result};
use cfg_if::cfg_if;
#[cfg(any(feature = "aya", feature = "libbpf", feature = "libbpf-skel"))]
use enum_dispatch::enum_dispatch;
use tracing::{debug, info};

use crate::skel::einat;
use crate::skel::einat::types::{
    ip_address_from_inet_addr, BindingFlags, ExternalConfig, ExternalFlags, InetAddr,
};
use crate::skel::einat::{EinatEbpf, EinatEbpfInet, EinatEbpfSkel};
use crate::skel::{
    EbpfHashMap, EbpfHashMapMut, EbpfLpmTrieMut, EbpfMapFlags, MapBindingKey, MapBindingValue,
    MapCtKey,
};
use crate::utils::{IpAddress, IpNetwork, MapChange, PrefixMapDiff};

#[allow(clippy::large_enum_variant)]
#[cfg_attr(
    any(feature = "aya", feature = "libbpf", feature = "libbpf-skel"),
    enum_dispatch(EinatInstanceT)
)]
pub enum EinatInstanceEnum {
    #[cfg(feature = "aya")]
    Aya(EinatInstance<einat::aya::EinatAya>),
    #[cfg(feature = "libbpf")]
    Libbpf(EinatInstance<einat::libbpf::EinatLibbpf>),
    #[cfg(feature = "libbpf-skel")]
    LibbpfSkel(EinatInstance<einat::libbpf_skel::EinatLibbpfSkel>),
}

pub struct EinatInstance<T: EinatEbpfSkel> {
    skel: T,
    config: Option<RuntimeConfig>,
    links: Option<T::Links>,
}

#[cfg_attr(
    any(feature = "aya", feature = "libbpf", feature = "libbpf-skel"),
    enum_dispatch
)]
pub trait EinatInstanceT: Sized {
    fn config(&self) -> Option<&RuntimeConfig>;

    fn apply_config(&mut self, config: RuntimeConfig) -> Result<()>;

    fn attach(&mut self, if_name: &str, if_index: u32) -> Result<()>;

    fn detach(&mut self) -> Result<()>;
}

impl EinatInstanceEnum {
    pub fn default_load(config: LoadConfig) -> Result<Self> {
        cfg_if! {
            if #[cfg(feature = "aya")] {
                Ok(Self::Aya(EinatInstance::load(config)?))
            } else if #[cfg(feature = "libbpf")] {
                Ok(Self::Libbpf(EinatInstance::load(config)?))
            } else if #[cfg(feature = "libbpf-skel")] {
                Ok(Self::LibbpfSkel(EinatInstance::load(config)?))
            } else {
                Err(anyhow!("no available eBPF loading backend"))
            }
        }
    }
}

impl<T: EinatEbpfSkel> EinatInstance<T> {
    pub fn load(config: LoadConfig) -> Result<Self> {
        let start = Instant::now();

        let skel = T::load(config.0)?;

        info!(
            "einat eBPF instance loaded in {:?} with {} loader",
            start.elapsed(),
            T::NAME
        );

        Ok(Self {
            skel,
            config: None,
            links: None,
        })
    }
}

impl<T: EinatEbpfSkel> EinatInstanceT for EinatInstance<T> {
    fn config(&self) -> Option<&RuntimeConfig> {
        self.config.as_ref()
    }

    fn apply_config(&mut self, config: RuntimeConfig) -> Result<()> {
        apply_inet_config(
            &mut self.skel,
            self.config.as_ref().map(|config| &config.v4),
            &config.v4,
        )?;

        #[cfg(feature = "ipv6")]
        apply_inet_config(
            &mut self.skel,
            self.config.as_ref().map(|config| &config.v6),
            &config.v6,
        )?;

        self.config = Some(config);
        Ok(())
    }

    fn attach(&mut self, if_name: &str, if_index: u32) -> Result<()> {
        if self.links.is_some() {
            return Err(anyhow!("already attached"));
        }
        let links = self.skel.attach(if_name, if_index)?;
        self.links = Some(links);
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        if let Some(links) = self.links.take() {
            self.skel.detach(links)?;
        }
        Ok(())
    }
}

fn apply_inet_config<P: InetPrefix, T: EinatEbpf + EinatEbpfInet<P>>(
    skel: &mut T,
    old: Option<&InetConfig<P>>,
    config: &InetConfig<P>,
) -> Result<()> {
    let default = Default::default();
    let dest_config_diff = PrefixMapDiff::new(
        old.map_or(&default, |old| &old.dest_config),
        &config.dest_config,
    );

    let default = Default::default();
    let external_config_diff = PrefixMapDiff::new(
        old.map_or(&default, |old| &old.external_config),
        &config.external_config,
    );

    let set_addr = old.map_or(true, |old| old.external_addr != config.external_addr);
    if set_addr {
        if !config.external_addr.is_unspecified() {
            info!(
                "setting default external address to {}",
                config.external_addr.addr()
            );
        }

        skel.with_updating_wait(|skel| skel.set_external_addr(config.external_addr))??;
    }

    for change in dest_config_diff {
        match change {
            MapChange::Insert { key, value } | MapChange::Update { key, value, .. } => {
                debug!("update dest config of {}", key);
                skel.map_dest_config()
                    .update(key, value, EbpfMapFlags::ANY)?;
            }
            MapChange::Delete { key, .. } => {
                debug!("delete dest config of {}", key);
                skel.map_dest_config().delete(key)?;
            }
        }
    }

    for change in external_config_diff {
        match change {
            MapChange::Insert { key, value } => {
                debug!("insert external config of {}", key);
                skel.map_external_config()
                    .update(key, value, EbpfMapFlags::NO_EXIST)?;
            }
            MapChange::Update { key, old, value } => {
                debug!("update external config of {}", key);
                skel.with_updating_wait(|skel| -> Result<()> {
                    remove_binding_and_ct_entries(skel, key, old)?;
                    skel.map_external_config()
                        .update(key, value, EbpfMapFlags::EXIST)
                })??;
            }
            MapChange::Delete { key, old } => {
                debug!("delete external config of {}", key);
                skel.with_updating_wait(|skel| -> Result<()> {
                    skel.map_external_config().delete(key)?;
                    remove_binding_and_ct_entries(skel, key, old)
                })??;
            }
        }
    }

    Ok(())
}

// FIXME: matching network prefix instead of simple `==` comparison
fn remove_binding_and_ct_entries<T: EinatEbpf, P: InetPrefix>(
    skel: &mut T,
    external_network: &P,
    external_config: &ExternalConfig,
) -> Result<()> {
    // there should be no record for internal addresses as external source
    if external_config.flags.contains(ExternalFlags::IS_INTERNAL) {
        return Ok(());
    }

    let addr_flag = if IpNetwork::prefix_len(external_network) == Ipv4Addr::LEN {
        BindingFlags::ADDR_IPV4
    } else {
        BindingFlags::ADDR_IPV6
    };

    // cleanup NAT binding records

    let mut to_delete = Vec::new();

    let addr_matches = |flags: &BindingFlags, inet_addr: &InetAddr| {
        if flags.contains(addr_flag) {
            let addr = ip_address_from_inet_addr::<P>(inet_addr);
            external_network.contains(&addr)
        } else {
            false
        }
    };

    for key in skel.map_binding().keys() {
        let key_owned = key?;
        let key: &MapBindingKey = key_owned.borrow();

        if key.flags.contains(BindingFlags::ORIG_DIR) {
            if let Some(binding) = skel.map_binding().lookup(key, EbpfMapFlags::ANY)? {
                let binding: &MapBindingValue = binding.borrow();

                if addr_matches(&binding.flags, &binding.to_addr) {
                    to_delete.push(key_owned);
                }
            }
        } else if addr_matches(&key.flags, &key.from_addr) {
            to_delete.push(key_owned);
        }
    }

    skel.map_binding_mut()
        .delete_batch(to_delete.iter().map(|i| i.borrow()), EbpfMapFlags::ANY)?;

    // cleanup CT records

    let mut to_delete = Vec::new();

    for key in skel.map_ct().keys() {
        let key_owned = key?;
        let ct: &MapCtKey = key_owned.borrow();
        if addr_matches(&ct.flags, &ct.external.src_addr) {
            to_delete.push(key_owned);
        }
    }

    skel.map_ct_mut()
        .delete_batch(to_delete.iter().map(|i| i.borrow()), EbpfMapFlags::ANY)?;

    Ok(())
}

#[cfg(not(any(feature = "aya", feature = "libbpf", feature = "libbpf-skel")))]
/// Dummy impl if no any enabled eBPF loading backend
impl EinatInstanceT for EinatInstanceEnum {
    fn config(&self) -> Option<&RuntimeConfig> {
        unimplemented!()
    }

    fn apply_config(&mut self, _config: RuntimeConfig) -> Result<()> {
        unimplemented!()
    }

    fn attach(&mut self, _if_name: &str, _if_index: u32) -> Result<()> {
        unimplemented!()
    }

    fn detach(&mut self) -> Result<()> {
        unimplemented!()
    }
}
