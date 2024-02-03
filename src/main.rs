// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
mod cleaner;
mod skel;

use std::error::Error;
use std::net::IpAddr;
use std::os::fd::AsFd;

use bytemuck::bytes_of;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{TcHookBuilder, TC_EGRESS, TC_INGRESS};

use skel::*;

const HELP: &str = "\
BPF Full Cone NAT

USAGE:
  bpf-full-cone-nat [OPTIONS]

OPTIONS:
  -h, --help               Print this message
  -i, --ifname             Network interface name, e.g. eth0
      --ifindex            Network interface index number, e.g. 2
      --external-ip        Static external IP address
      --bpf-log <level>    BPF tracing log level, 0 to 5, defaults to 2, WARN
";

#[derive(Default)]
struct Args {
    if_index: Option<u32>,
    if_name: Option<String>,
    ip_addr: Option<IpAddr>,
    log_level: Option<u8>,
}

fn parse_env_args() -> Result<Args, Box<dyn Error>> {
    use lexopt::prelude::*;
    let mut args = Args::default();
    let mut parser = lexopt::Parser::from_env();
    while let Some(opt) = parser.next()? {
        match opt {
            Short('h') | Long("help") => {
                print!("{}", HELP);
                std::process::exit(0);
            }
            Short('i') | Long("ifname") => {
                args.if_name = Some(parser.value()?.parse()?);
            }
            Long("ifindex") => {
                args.if_index = Some(parser.value()?.parse()?);
            }
            Long("external-ip") => {
                args.ip_addr = Some(parser.value()?.parse()?);
            }
            Long("bpf-log") => {
                args.log_level = Some(parser.value()?.parse()?);
            }
            _ => return Err(opt.unexpected().into()),
        }
    }

    Ok(args)
}

async fn signal_monitor() -> Result<(), Box<dyn Error>> {
    tokio::signal::ctrl_c().await?;
    Err("terminating".into())
}

fn set_map_config(skel: &mut FullConeNatSkel, ip_addr: IpAddr) -> Result<(), Box<dyn Error>> {
    match ip_addr {
        IpAddr::V4(ip) => {
            skel.data_mut().g_ipv4_external_addr = u32::from_ne_bytes(ip.octets());
            let lpm_key = Ipv4LpmKey {
                prefix_len: 32,
                ip: ip.octets(),
            };

            let mut ext_config = ExternalConfig::default();
            ext_config.udp_range[0] = PortRange {
                from_port: 20000,
                to_port: 23999,
            };
            ext_config.udp_range[1] = PortRange {
                from_port: 25000,
                to_port: 29999,
            };
            ext_config.udp_range_len = 2;
            ext_config.icmp_range[0] = PortRange {
                from_port: u16::MIN,
                to_port: u16::MAX,
            };
            ext_config.icmp_range_len = 1;

            let dest_config = DestConfig {
                flags: 1, // hairpin
            };
            skel.maps().map_ipv4_external_config().update(
                bytes_of(&lpm_key),
                bytes_of(&ext_config),
                libbpf_rs::MapFlags::ANY,
            )?;

            skel.maps().map_ipv4_dest_config().update(
                bytes_of(&lpm_key),
                bytes_of(&dest_config),
                libbpf_rs::MapFlags::ANY,
            )?;
        }
        IpAddr::V6(_ip6) => {
            todo!("IPv6 SNAT not implemented yet")
        }
    };

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_env_args()?;
    if args.if_index.is_none() && args.if_name.is_none() {
        eprint!("{}", HELP);
        std::process::exit(1);
    } else if args.if_index.is_some() && args.if_name.is_some() {
        eprintln!("specify either -i/--ifname or --ifindex but not both");
        std::process::exit(1);
    }

    let Some(ip_addr) = args.ip_addr else {
        eprintln!("static external IP address required for now");
        std::process::exit(1);
    };

    let if_index = if let Some(i) = args.if_index {
        i
    } else {
        let name = args.if_name.as_ref().unwrap().as_str();
        nix::net::if_::if_nametoindex(name)?
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let mut skel_builder = FullConeNatSkelBuilder::default();

    skel_builder.obj_builder.debug(true);

    let mut open_skel = skel_builder.open()?;

    open_skel.rodata_mut().ENABLE_FIB_LOOKUP_SRC = 0;

    let mut skel = open_skel.load()?;

    skel.data_mut().g_log_level = args.log_level.unwrap_or(5).min(5);
    set_map_config(&mut skel, ip_addr)?;

    let progs = skel.progs();

    let mut ingress = TcHookBuilder::new(progs.ingress_rev_snat().as_fd())
        .ifindex(if_index as _)
        .replace(true)
        .hook(TC_INGRESS);

    let mut egress = TcHookBuilder::new(progs.egress_snat().as_fd())
        .ifindex(if_index as _)
        .replace(true)
        .hook(TC_EGRESS);

    ingress.create().unwrap();
    egress.create().unwrap();

    ingress.attach().unwrap();
    egress.attach().unwrap();

    if let Err(e) = rt.block_on(async {
        tokio::try_join!(
            signal_monitor(),
            cleaner::clean_ct_task(&mut skel, if_index)
        )
    }) {
        eprintln!("{:?}", e);
    }

    egress.detach().unwrap();
    ingress.detach().unwrap();
    egress.destroy().unwrap();
    ingress.destroy().unwrap();

    Ok(())
}
