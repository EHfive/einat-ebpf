// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
mod config;
mod instance;
mod monitor;
mod skel;
mod utils;

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use futures_util::StreamExt;

use config::{Config, ConfigNetIf, NetIfId};
use instance::Instance;
use monitor::{IfAddresses, MonitorEvent};

const HELP: &str = "\
BPF Full Cone NAT

USAGE:
  bpf-full-cone-nat [OPTIONS]

OPTIONS:
  -h, --help               Print this message
  -c, --config <file>      Path to configuration file
  -i, --ifname             Network interface name, e.g. eth0
      --ifindex            Network interface index number, e.g. 2
      --nat44              Enable NAT44/NAPT44 for specified network interface
      --bpf-log <level>    BPF tracing log level, 0 to 5, defaults to 0, disabled
";

#[derive(Default)]
struct Args {
    config_file: Option<PathBuf>,
    if_index: Option<u32>,
    if_name: Option<String>,
    nat44: bool,
    nat66: bool,
    log_level: Option<u8>,
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
            Short('c') | Long("config") => {
                args.config_file = Some(parser.value()?.parse()?);
            }
            Short('i') | Long("ifname") => {
                args.if_name = Some(parser.value()?.parse()?);
            }
            Long("ifindex") => {
                args.if_index = Some(parser.value()?.parse()?);
            }
            Long("nat44") => {
                args.nat44 = true;
            }
            Long("nat66") => {
                args.nat66 = true;
            }
            Long("bpf-log") => {
                args.log_level = Some(parser.value()?.parse()?);
            }
            _ => return Err(opt.unexpected().into()),
        }
    }

    Ok(args)
}

struct IfContext {
    if_index: u32,
    inst: Instance,
    addresses: IfAddresses,
}

async fn daemon(config: &Config) -> Result<()> {
    let (monitor_task, query_addr, events) = monitor::spawn()?;

    let mut inst_configs = HashMap::with_capacity(config.interfaces.len());

    for if_config in &config.interfaces {
        let if_index = if_config.interface.resolve_index()?;
        let addresses = query_addr.query_all_addresses(if_index).await?;
        let inst_config =
            instance::InstanceConfig::try_from(if_index, if_config, &config.defaults, &addresses)?;
        inst_configs.insert(if_index, (inst_config, addresses));
    }

    let need_monitor = inst_configs
        .values()
        .any(|(inst_config, _)| !inst_config.is_static());

    let tasks: Vec<_> = inst_configs
        .into_iter()
        .map(|(if_index, (inst_config, addresses))| {
            tokio::task::spawn_blocking(move || -> Result<_> {
                let inst = inst_config.load()?;
                Ok(IfContext {
                    if_index,
                    inst,
                    addresses,
                })
            })
        })
        .collect();

    let mut contexts = HashMap::with_capacity(tasks.len());
    for task in tasks {
        let ctx = task.await??;
        contexts.insert(ctx.if_index, ctx);
    }

    for ctx in contexts.values_mut() {
        ctx.inst.attach()?;
    }

    let monitor = async {
        if !need_monitor {
            std::future::pending::<()>().await;
            return Ok(());
        }

        futures_util::pin_mut!(events);
        while let Some(event) = events.next().await {
            let MonitorEvent::ChangeAddress { if_index } = event;

            if let Some(ctx) = contexts.get_mut(&if_index) {
                let new_addresses = query_addr.query_all_addresses(if_index).await?;
                if new_addresses.ipv4 != ctx.addresses.ipv4 {
                    eprintln!(
                        "IPv4 addresses {:?} -> {:?}",
                        ctx.addresses.ipv4, new_addresses.ipv4
                    );
                    ctx.inst.reconfigure_v4_addresses(&new_addresses.ipv4)?;
                    ctx.addresses.ipv4 = new_addresses.ipv4;
                }
                #[cfg(feature = "ipv6")]
                if new_addresses.ipv6 != ctx.addresses.ipv6 {
                    eprintln!(
                        "IPv6 addresses {:?} -> {:?}",
                        ctx.addresses.ipv6, new_addresses.ipv6
                    );
                    ctx.inst.reconfigure_v6_addresses(&new_addresses.ipv6)?;
                    ctx.addresses.ipv6 = new_addresses.ipv6;
                }
            }
        }

        Result::<()>::Ok(())
    };

    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res?;
            Result::<()>::Ok(())
        }
        res = monitor => {
            res
        }
    }?;

    for ctx in contexts.values_mut() {
        ctx.inst.detach()?;
    }

    monitor_task.abort();
    Ok(())
}

fn main() -> Result<()> {
    let args = parse_env_args()?;

    let mut config: Config = if let Some(config_path) = args.config_file {
        let text = std::fs::read_to_string(config_path)?;
        toml::from_str(&text)?
    } else {
        Config::default()
    };

    if args.if_index.is_some() || args.if_name.is_some() {
        let interface = if let Some(if_index) = args.if_index {
            NetIfId::Index { if_index }
        } else if let Some(if_name) = args.if_name {
            NetIfId::Name { if_name }
        } else {
            unreachable!()
        };

        let nat44 = args.nat44 || !args.nat66;
        let nat66 = args.nat66;

        let if_config = ConfigNetIf {
            interface,
            bpf_log_level: args.log_level,
            nat44,
            nat66,
            default_externals: true,
            ..Default::default()
        };

        config.interfaces.push(if_config);
    }

    if config.interfaces.is_empty() {
        return Err(anyhow::anyhow!("No network interface specified"));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(daemon(&config))
}
