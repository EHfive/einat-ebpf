// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
mod config;
mod instance;
mod macros;
mod route;
mod skel;
mod utils;

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use futures_util::StreamExt;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use ipnet::{IpNet, Ipv4Net};
#[cfg(any(feature = "libbpf", feature = "libbpf-skel"))]
use libbpf_rs::PrintLevel;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use config::{BpfLoader, Config, ConfigDefaults, ConfigNetIf, IpProtocol, ProtoRange};
use instance::{EinatInstance, EinatInstanceEnum, EinatInstanceT, LoadConfig, RuntimeConfigEval};
use route::{HairpinRouting, IfAddresses, MonitorEvent, PacketEncap, RouteHelper};

const HELP: &str = "\
einat - An eBPF-based Endpoint-Independent NAT

USAGE:
  einat [OPTIONS]

OPTIONS:
  -h, --help                   Print this message
  -c, --config <file>          Path to configuration file
  -i, --ifname <name>          External network interface name, e.g. eth0
      --nat44                  Enable NAT44/NAPT44 for specified network interface, enabled by
                               default if neither --nat44 nor --nat66 are specified
      --nat66                  Enable NAT66/NAPT66 for specified network interface
      --ports <range> ...      External TCP/UDP port ranges, defaults to 20000-29999
      --hairpin-if <name> ...  Hairpin internal network interface names, e.g. lo, lan0
      --internal <CIDR> ...    Perform source NAT for these internal networks only
      --bpf-loader <loader>    BPF loading backend used, one of aya or libbpf
  -v, --version                Print einat version
";

#[derive(Default)]
struct Args {
    config_file: Option<PathBuf>,
    if_name: Option<String>,
    nat44: bool,
    nat66: bool,
    ports: Vec<ProtoRange>,
    hairpin_if_names: Vec<String>,
    snat_internals: Vec<IpNet>,
    log_level: Option<u8>,
    bpf_loader: Option<BpfLoader>,
}

fn parse_env_args() -> Result<Args> {
    use lexopt::prelude::*;
    let mut args = Args::default();
    let mut parser = lexopt::Parser::from_env();
    while let Some(opt) = parser.next()? {
        match opt {
            Short('h') | Long("help") => {
                print!("{}", HELP);
                std::process::exit(0);
            }
            Short('v') | Long("version") => {
                println!("{}", env!("EINAT_BUILD_INFO"));
                std::process::exit(0);
            }
            Short('c') | Long("config") => {
                args.config_file = Some(parser.value()?.into());
            }
            Short('i') | Long("ifname") => {
                args.if_name = Some(parser.value()?.parse()?);
            }
            Long("nat44") => {
                args.nat44 = true;
            }
            Long("nat66") => {
                args.nat66 = true;
            }
            Long("ports") => {
                let ports: Result<Vec<_>, _> = parser.values()?.map(|s| s.parse()).collect();
                args.ports = ports?;
            }
            Long("hairpin-if") => {
                let names: Result<Vec<_>, _> = parser.values()?.map(|s| s.parse()).collect();
                args.hairpin_if_names = names?;
            }
            Long("internal") => {
                let internals: Result<Vec<_>, _> = parser.values()?.map(|s| s.parse()).collect();
                args.snat_internals = internals?;
            }
            Long("bpf-log") => {
                args.log_level = Some(parser.value()?.parse()?);
            }
            Long("bpf-loader") => {
                args.bpf_loader = Some(parser.value()?.parse()?);
            }
            _ => return Err(opt.unexpected().into()),
        }
    }

    Ok(args)
}

#[derive(Default)]
struct DaemonContext {
    if_contexts: HashMap<String, IfContext>,
}

struct IfContextActive {
    if_index: u32,
    addresses: IfAddresses,
    v4_hairpin_routing: Option<HairpinRouting<Ipv4Net>>,
    #[cfg(feature = "ipv6")]
    v6_hairpin_routing: Option<HairpinRouting<Ipv6Net>>,
}

struct IfContext {
    if_name: String,
    defaults: ConfigDefaults,
    config: ConfigNetIf,
    config_evaluator: RuntimeConfigEval,
    inst: Option<(EinatInstanceEnum, PacketEncap)>,
    active: Option<IfContextActive>,
    rt_helper: RouteHelper,
}

impl DaemonContext {
    fn insert_context(&mut self, ctx: IfContext) -> Option<IfContext> {
        self.if_contexts.insert(ctx.if_name.clone(), ctx)
    }

    fn get_context_by_name(&mut self, if_name: &str) -> Option<&mut IfContext> {
        self.if_contexts.get_mut(if_name)
    }

    fn get_context_by_index(&mut self, if_index: u32) -> Option<&mut IfContext> {
        self.if_contexts
            .values_mut()
            .find(|ctx| ctx.match_if_index(if_index))
    }
}

impl IfContext {
    fn new(defaults: ConfigDefaults, config: ConfigNetIf, rt_helper: RouteHelper) -> Result<Self> {
        let config_evaluator = RuntimeConfigEval::try_from(&config, &defaults)?;

        Ok(Self {
            if_name: config.if_name.clone(),
            defaults,
            config,
            config_evaluator,
            inst: None,
            active: None,
            rt_helper,
        })
    }

    fn match_if_index(&self, other: u32) -> bool {
        if let Some(IfContextActive { if_index, .. }) = self.active {
            return if_index == other;
        }
        false
    }

    async fn reconfigure(&mut self) -> Result<()> {
        let Some(link_info) = self.rt_helper.query_link_info(&self.if_name).await.unwrap() else {
            info!("interface {} not exists", self.if_name);
            return self.deconfigure().await;
        };
        if !link_info.is_up() {
            info!("interface {} is not up", self.if_name);
            return self.deconfigure().await;
        }
        let if_index = link_info.index();
        if let Some(active) = &mut self.active {
            if active.if_index != if_index {
                warn!(
                    "interface index of {} out of sync, {} -> {}",
                    self.if_name, active.if_index, if_index
                );
                self.deconfigure().await?;
                // re-init
            } else {
                self.reconfigure_hairpin().await?;
                return Ok(());
            }
        }

        info!(
            "attaching einat eBPF programs to interface {}",
            self.if_name
        );

        let addresses = self.rt_helper.query_all_addresses(if_index).await?;
        let is_new = self.ensure_instance(link_info.encap(), &addresses).await?;

        let addresses = if is_new {
            addresses
        } else {
            // re-fetch addresses and re-apply config if it's old instance
            Default::default()
        };

        let (inst, _) = self.inst.as_mut().expect("instance ensured");
        inst.attach(&self.if_name, if_index)?;

        self.active = Some(IfContextActive {
            addresses,
            if_index,
            v4_hairpin_routing: self.v4_hairpin_routing(if_index),
            #[cfg(feature = "ipv6")]
            v6_hairpin_routing: self.v6_hairpin_routing(if_index),
        });

        if is_new {
            self.reconfigure_hairpin().await?;
        } else {
            self.reconfigure_addresses().await?;
        }

        Ok(())
    }

    fn v4_hairpin_routing(&self, if_index: u32) -> Option<HairpinRouting<Ipv4Net>> {
        let hairpin_config = &self.config.ipv4_hairpin_route;
        let internal_if_names = hairpin_config.internal_if_names.clone();
        let enable = hairpin_config.enable == Some(true)
            || hairpin_config.enable != Some(false) && !internal_if_names.is_empty();
        if !enable {
            return None;
        }
        let ip_rule_pref = hairpin_config
            .ip_rule_pref
            .unwrap_or(self.defaults.ipv4_hairpin_rule_pref);
        let local_ip_rule_pref = self.defaults.ipv4_local_rule_pref;
        if ip_rule_pref >= local_ip_rule_pref {
            warn!(
                "Hairpinning IPv4 route rule priority {} is not less than local IP rule priority {}",
                ip_rule_pref, local_ip_rule_pref,
            );
        }

        let table_id = hairpin_config
            .table_id
            .unwrap_or(self.defaults.ipv4_hairpin_table_id)
            .get();

        Some(HairpinRouting::new(
            self.rt_helper.clone(),
            if_index,
            table_id,
            ip_rule_pref,
            local_ip_rule_pref,
            internal_if_names,
            hairpin_config.ip_protocols.clone(),
        ))
    }

    #[cfg(feature = "ipv6")]
    fn v6_hairpin_routing(&self, if_index: u32) -> Option<HairpinRouting<Ipv6Net>> {
        let hairpin_config = &self.config.ipv6_hairpin_route;
        let internal_if_names = hairpin_config.internal_if_names.clone();
        let enable = hairpin_config.enable == Some(true)
            || hairpin_config.enable != Some(false) && !internal_if_names.is_empty();
        if !enable {
            return None;
        }
        let ip_rule_pref = hairpin_config
            .ip_rule_pref
            .unwrap_or(self.defaults.ipv6_hairpin_rule_pref);
        let local_ip_rule_pref = self.defaults.ipv6_local_rule_pref;
        if ip_rule_pref >= local_ip_rule_pref {
            warn!(
                "Hairpinning IPv6 route rule priority {} is not less than local IP rule priority {}",
                ip_rule_pref, local_ip_rule_pref,
            );
        }

        let table_id = hairpin_config
            .table_id
            .unwrap_or(self.defaults.ipv6_hairpin_table_id)
            .get();

        Some(HairpinRouting::new(
            self.rt_helper.clone(),
            if_index,
            table_id,
            ip_rule_pref,
            local_ip_rule_pref,
            internal_if_names,
            hairpin_config.ip_protocols.clone(),
        ))
    }

    async fn ensure_instance(
        &mut self,
        if_encap: PacketEncap,
        addresses: &IfAddresses,
    ) -> Result<bool> {
        if let Some((_, curr_encap)) = &mut self.inst {
            // reuse instance if const configs have not changed
            if *curr_encap == if_encap {
                return Ok(false);
            }
        }

        let has_eth_encap = match if_encap {
            PacketEncap::Ethernet => true,
            PacketEncap::BareIp => false,
            PacketEncap::Unsupported => {
                return Err(anyhow::anyhow!(
                    "Interface has unsupported packet encapsulation"
                ))
            }
            PacketEncap::Unknown => {
                warn!("unknown interface packet encapsulation type, fallback to no encap");
                false
            }
        };

        let load_config = LoadConfig::from(&self.config, has_eth_encap);
        let rt_config = self.config_evaluator.eval(addresses);
        let loader = self.config.bpf_loader;

        let inst = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut inst = match loader {
                #[cfg(feature = "aya")]
                Some(BpfLoader::Aya) => EinatInstanceEnum::Aya(EinatInstance::load(load_config)?),
                #[cfg(feature = "libbpf")]
                Some(BpfLoader::Libbpf) => {
                    EinatInstanceEnum::Libbpf(EinatInstance::load(load_config)?)
                }
                #[cfg(feature = "libbpf-skel")]
                Some(BpfLoader::LibbpfSkel) => {
                    EinatInstanceEnum::LibbpfSkel(EinatInstance::load(load_config)?)
                }
                _ => EinatInstanceEnum::default_load(load_config)?,
            };

            inst.apply_config(rt_config)?;
            Ok(inst)
        })
        .await??;

        self.inst = Some((inst, if_encap));
        Ok(true)
    }

    async fn reconfigure_hairpin(&mut self) -> Result<()> {
        let Some(ctx) = &mut self.active else {
            return Ok(());
        };
        let Some((inst, _)) = &mut self.inst else {
            return Ok(());
        };
        if let Some(hairpin_routing) = &mut ctx.v4_hairpin_routing {
            if let Err(e) = hairpin_routing
                .reconfigure(
                    inst.config()
                        .expect("config not applied")
                        .v4
                        .hairpin_dests(),
                )
                .await
            {
                error!("failed to reconfigure IPv4 hairpin routing: {}", e);
            }
        }

        #[cfg(feature = "ipv6")]
        if let Some(hairpin_routing) = &mut ctx.v6_hairpin_routing {
            if let Err(e) = hairpin_routing
                .reconfigure(
                    inst.config()
                        .expect("config not applied")
                        .v6
                        .hairpin_dests(),
                )
                .await
            {
                error!("failed to reconfigure IPv6 hairpin routing: {}", e);
            }
        }
        Ok(())
    }

    async fn reconfigure_addresses(&mut self) -> Result<()> {
        let Some(ctx) = &mut self.active else {
            return Ok(());
        };
        let Some((inst, _)) = &mut self.inst else {
            return Ok(());
        };

        let new_addresses = self.rt_helper.query_all_addresses(ctx.if_index).await?;

        debug!("addresses {:?} -> {:?}", ctx.addresses, new_addresses);

        if new_addresses != ctx.addresses {
            let rt_config = self.config_evaluator.eval(&new_addresses);
            inst.apply_config(rt_config)?;
            ctx.addresses = new_addresses;
        }

        self.reconfigure_hairpin().await?;

        Ok(())
    }

    async fn deconfigure(&mut self) -> Result<()> {
        if let Some((inst, _)) = &mut self.inst {
            let _ = inst.detach();
        }
        let Some(ctx) = self.active.take() else {
            return Ok(());
        };
        info!("detaching interface {}", self.if_name);

        if let Some(mut hairpin_routing) = ctx.v4_hairpin_routing {
            let _ = hairpin_routing.deconfigure().await;
        }

        #[cfg(feature = "ipv6")]
        if let Some(mut hairpin_routing) = ctx.v6_hairpin_routing {
            let _ = hairpin_routing.deconfigure().await;
        }

        Ok(())
    }
}

async fn daemon(config: Config, context: &mut DaemonContext) -> Result<JoinHandle<()>> {
    let (monitor_task, events) = route::spawn_monitor()?;
    let rt_helper = RouteHelper::spawn()?;

    for if_config in config.interfaces {
        let ctx = IfContext::new(config.defaults.clone(), if_config, rt_helper.clone())?;
        context.insert_context(ctx);
    }

    for ctx in context.if_contexts.values_mut() {
        if let Err(e) = ctx.reconfigure().await {
            error!("failed to configure interface {}: {}", ctx.if_name, e);
        }
    }

    drop(rt_helper);

    let monitor = async {
        futures_util::pin_mut!(events);
        while let Some(event) = events.next().await {
            match event {
                MonitorEvent::ChangeAddress { if_index } => {
                    if let Some(ctx) = context.get_context_by_index(if_index) {
                        if let Err(e) = ctx.reconfigure_addresses().await {
                            error!(
                                "failed to reconfigure addresses for interface {}: {}",
                                ctx.if_name, e
                            );
                        };
                    }
                }
                MonitorEvent::ChangeLink { if_name } => {
                    if let Some(ctx) = context.get_context_by_name(&if_name) {
                        if let Err(e) = ctx.reconfigure().await {
                            error!("failed to reconfigure interface {}: {}", ctx.if_name, e);
                        }
                    }
                }
                MonitorEvent::DelLink { if_name } => {
                    if let Some(ctx) = context.get_context_by_name(&if_name) {
                        let _ = ctx.deconfigure().await;
                    }
                }
            }
        }

        Result::<()>::Ok(())
    };

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {
            Result::<()>::Ok(())
        }
        _ = sigterm.recv() => {
            Result::<()>::Ok(())
        }
        res = monitor => {
            res
        }
    }?;

    Ok(monitor_task)
}

async fn daemon_guard(config: Config) -> Result<()> {
    let mut context = DaemonContext::default();

    let res = daemon(config, &mut context).await;

    for ctx in context.if_contexts.values_mut() {
        if let Err(e) = ctx.deconfigure().await {
            error!("failed to cleanup context: {}", e);
        };
    }

    res?.abort();
    Ok(())
}

fn tracing_init() -> Result<()> {
    tracing_subscriber::fmt::init();

    #[cfg(any(feature = "libbpf", feature = "libbpf-skel"))]
    libbpf_rs::set_print(Some((PrintLevel::Debug, |level, msg| {
        let span = tracing::span!(tracing::Level::ERROR, "libbpf");
        let _enter = span.enter();

        let msg = msg.trim_start_matches("libbpf: ").trim_end_matches('\n');

        if let Some(msg) = msg.strip_prefix("Kernel error message: ") {
            // Avoid showing harmless "Exclusivity flag on, cannot modify" in default "INFO" level
            debug!("libbpf netlink ACK error message: {}", msg);
            return;
        }

        match level {
            PrintLevel::Info => info!("{}", msg),
            PrintLevel::Warn => warn!("{}", msg),
            PrintLevel::Debug => debug!("{}", msg),
        }
    })));

    Ok(())
}

fn main() -> Result<()> {
    tracing_init()?;

    let args = parse_env_args()?;

    let mut config: Config = if let Some(config_path) = &args.config_file {
        let text = std::fs::read_to_string(config_path)?;
        toml::from_str(&text)?
    } else {
        Config::default()
    };

    if let Some(if_name) = args.if_name {
        if args.config_file.is_some() {
            return Err(anyhow::anyhow!(
                "Combining interface configuration from CLI options with configuration file is not allowed"
            ));
        }

        let nat44 = args.nat44 || !args.nat66;
        let nat66 = args.nat66;

        #[cfg(not(feature = "ipv6"))]
        if nat66 {
            warn!("NAT66 feature not enabled for this build, ignoring");
        }

        if !args.ports.is_empty() {
            config.defaults.tcp_ranges = args.ports.clone();
            config.defaults.udp_ranges = args.ports;
        }

        let hairpin_route = config::ConfigHairpinRoute {
            enable: None,
            internal_if_names: args.hairpin_if_names,
            ip_rule_pref: None,
            table_id: None,
            ip_protocols: vec![IpProtocol::Tcp, IpProtocol::Udp],
        };

        let if_config = ConfigNetIf {
            if_name,
            bpf_log_level: args.log_level,
            bpf_loader: args.bpf_loader,
            nat44,
            nat66,
            default_externals: true,
            snat_internals: args.snat_internals,
            ipv4_hairpin_route: hairpin_route.clone(),
            ipv6_hairpin_route: hairpin_route,
            ..Default::default()
        };

        config.interfaces = vec![if_config];
    }

    if config.interfaces.is_empty() {
        return Err(anyhow::anyhow!("No network interface specified"));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(daemon_guard(config))
}
