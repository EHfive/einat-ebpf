// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::fd::AsFd;

use anyhow::Result;
use libbpf_rs::{Program, TcHook, TcHookBuilder, TC_EGRESS, TC_INGRESS};

pub struct EinatLibbpfLinks {
    ingress_hook: TcHook,
    egress_hook: TcHook,
}

pub(super) fn attach(
    prog_ingress: &Program,
    prog_egress: &Program,
    if_index: u32,
) -> Result<EinatLibbpfLinks> {
    let mut ingress_hook = create_ingress_hook(prog_ingress, if_index)
        .create()?
        .attach()?;
    let egress_hook = create_egress_hook(prog_egress, if_index)
        .attach()
        .map_err(|e| {
            let _ = ingress_hook.detach();
            e
        })?;

    Ok(EinatLibbpfLinks {
        ingress_hook,
        egress_hook,
    })
}

pub(super) fn detach(mut links: EinatLibbpfLinks) -> Result<()> {
    let res = links.egress_hook.detach();
    links.ingress_hook.detach()?;
    Ok(res?)
}

fn create_ingress_hook(prog: &Program, if_index: u32) -> TcHook {
    TcHookBuilder::new(prog.as_fd())
        .ifindex(if_index as _)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_INGRESS)
}

fn create_egress_hook(prog: &Program, if_index: u32) -> TcHook {
    TcHookBuilder::new(prog.as_fd())
        .ifindex(if_index as _)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_EGRESS)
}
