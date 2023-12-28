// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
use std::error::Error;
use std::os::fd::AsFd;
use std::sync::mpsc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{TcHookBuilder, TC_EGRESS, TC_INGRESS};

mod nat {
    include!(concat!(env!("OUT_DIR"), "/full_cone_nat.skel.rs"));
}
use nat::*;

const BPF_F_NO_PREALLOC: u32 = 1;

const HELP: &str = "\
BPF Full Cone NAT

USAGE:
  bpf-full-cone-nat [OPTIONS]
OPTIONS:
  -h, --help        Print this message
  -i, --ifname      Network interface name, e.g. eth0
      --ifindex     Network interface index number, e.g. 2
  -m, --mode <id>   NAT filtering mode, 1 or 2
                        1 - Endpoint-Independent Filtering, default
                        2 - Address-Dependent Filtering
";

enum Filtering {
    EndpointIndependent,
    AddressDependent,
}
impl Filtering {
    fn to_mode_data(&self) -> u8 {
        use Filtering::*;
        match self {
            EndpointIndependent => 0,
            AddressDependent => 1,
        }
    }
}

#[derive(Default)]
struct Args {
    if_index: Option<u32>,
    if_name: Option<String>,
    mode: Option<Filtering>,
}

fn parse_env_args() -> Result<Args, lexopt::Error> {
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
            Short('m') | Long("mode") => {
                let num = parser.value()?.parse::<i32>()?;
                let mode = match num {
                    1 => Filtering::EndpointIndependent,
                    2 => Filtering::AddressDependent,
                    _ => {
                        eprintln!("invalid filtering mode id: {}", num);
                        std::process::exit(1);
                    }
                };
                args.mode.replace(mode);
            }
            _ => return Err(opt.unexpected()),
        }
    }

    Ok(args)
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

    let if_index = if let Some(i) = args.if_index {
        i
    } else {
        let name = args.if_name.as_ref().unwrap().as_str();
        nix::net::if_::if_nametoindex(name)?
    };

    let (tx, rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })?;

    let mut skel_builder = FullConeNatSkelBuilder::default();

    skel_builder.obj_builder.debug(true);

    let mut open_skel = skel_builder.open()?;
    open_skel.rodata_mut().nat_filtering_mode = args
        .mode
        .unwrap_or(Filtering::EndpointIndependent)
        .to_mode_data();
    open_skel
        .maps_mut()
        .mapping_table()
        .set_map_flags(BPF_F_NO_PREALLOC)?;
    open_skel
        .maps_mut()
        .conn_table()
        .set_map_flags(BPF_F_NO_PREALLOC)?;
    let skel = open_skel.load()?;

    let progs = skel.progs();

    let mut ingress = TcHookBuilder::new(progs.ingress_dnat().as_fd())
        .ifindex(if_index as _)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_INGRESS);

    let mut egress = TcHookBuilder::new(progs.egress_collect_snat().as_fd())
        .ifindex(if_index as _)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_EGRESS);

    ingress.create().unwrap();
    egress.create().unwrap();

    ingress.attach().unwrap();
    egress.attach().unwrap();

    rx.recv().unwrap();

    egress.detach().unwrap();
    ingress.destroy().unwrap();

    Ok(())
}
