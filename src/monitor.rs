// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use futures_util::{Stream, StreamExt, TryStreamExt};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{address::AddressAttribute, AddressFamily, RouteNetlinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{new_connection, Handle};
use tokio::task::JoinHandle;

const fn nl_mgrp(group: u32) -> u32 {
    if group > 31 {
        panic!("use netlink_sys::Socket::add_membership() for this group");
    }
    if group == 0 {
        0
    } else {
        1 << (group - 1)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IfAddresses {
    pub ipv4: Vec<Ipv4Addr>,
    #[cfg(feature = "ipv6")]
    pub ipv6: Vec<Ipv6Addr>,
}

pub struct QueryAddr {
    handle: Handle,
}

impl QueryAddr {
    pub async fn query_all_addresses(&self, if_index: u32) -> Result<IfAddresses> {
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(if_index)
            .execute();

        let mut res = IfAddresses::default();

        while let Some(msg) = addresses.try_next().await? {
            #[cfg(feature = "ipv6")]
            let matches = matches!(
                msg.header.family,
                AddressFamily::Inet | AddressFamily::Inet6
            );
            #[cfg(not(feature = "ipv6"))]
            let matches = matches!(msg.header.family, AddressFamily::Inet);
            if matches {
                for attr in msg.attributes {
                    #[allow(clippy::collapsible_match)]
                    if let AddressAttribute::Address(addr) = attr {
                        match addr {
                            IpAddr::V4(addr) => res.ipv4.push(addr),
                            #[cfg(feature = "ipv6")]
                            IpAddr::V6(addr) => res.ipv6.push(addr),
                            #[allow(unreachable_patterns)]
                            _ => (),
                        }
                    }
                }
            }
        }
        Ok(res)
    }
}

pub enum MonitorEvent {
    ChangeAddress { if_index: u32 },
}

/// This must be called from Tokio context.
pub fn spawn() -> Result<(JoinHandle<()>, QueryAddr, impl Stream<Item = MonitorEvent>)> {
    let (mut conn, handle, mut group_messages) = new_connection()?;

    #[cfg(feature = "ipv6")]
    let groups = nl_mgrp(libc::RTNLGRP_IPV4_IFADDR) | nl_mgrp(libc::RTNLGRP_IPV6_IFADDR);
    #[cfg(not(feature = "ipv6"))]
    let groups = nl_mgrp(libc::RTNLGRP_IPV4_IFADDR);

    let group_addr = SocketAddr::new(0, groups);
    conn.socket_mut().socket_mut().bind(&group_addr)?;

    let task = tokio::spawn(conn);

    let events = async_stream::stream!({
        while let Some((msg, _)) = group_messages.next().await {
            if let NetlinkPayload::InnerMessage(msg) = msg.payload {
                match msg {
                    RouteNetlinkMessage::NewAddress(msg)
                    | RouteNetlinkMessage::DelAddress(msg)
                    | RouteNetlinkMessage::GetAddress(msg) => {
                        yield MonitorEvent::ChangeAddress {
                            if_index: msg.header.index,
                        };
                    }
                    _ => (),
                }
            }
        }
    });

    Ok((task, QueryAddr { handle }, events))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_addr() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (_, query_addr, _) = spawn().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                query_addr.query_all_addresses(1).await.unwrap();
            })
            .await
            .unwrap();
        });
    }
}
