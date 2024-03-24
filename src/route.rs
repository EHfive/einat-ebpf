// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use futures_util::{Stream, StreamExt, TryStreamExt};
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{
    address::AddressAttribute,
    link::LinkAttribute,
    neighbour::{NeighbourMessage, NeighbourState},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol},
    rule::{RuleAction, RuleAttribute, RuleMessage},
    AddressFamily, IpProtocol as RouteIpProtocol, RouteNetlinkMessage,
};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{new_connection, Handle, IpVersion, NeighbourAddRequest, RouteAddRequest};
use tokio::task::JoinHandle;

use crate::config::IpProtocol;
use crate::utils::IpNetwork;

impl From<IpProtocol> for RouteIpProtocol {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Tcp => RouteIpProtocol::Tcp,
            IpProtocol::Udp => RouteIpProtocol::Udp,
            IpProtocol::Icmp => RouteIpProtocol::Icmp,
        }
    }
}

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

#[derive(Debug, Clone)]
pub struct RouteHelper {
    handle: Handle,
}

const ROUTE_LOCAL_TABLE_ID: u32 = 255;
const LOCAL_RULE_PRIORITY: u32 = 200;
const HAIRPIN_RULE_PRIORITY: u32 = 100;

impl RouteHelper {
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

    async fn local_ip_rules(&self, is_ipv4: bool) -> Result<Vec<(RuleMessage, u32)>> {
        let ip_version = if is_ipv4 {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        let mut s = self.handle.rule().get(ip_version).execute();

        let mut res = Vec::new();

        while let Some(rule) = s.try_next().await? {
            if rule.header.table == ROUTE_LOCAL_TABLE_ID as _
                && rule.header.action == RuleAction::ToTable
                && rule
                    .attributes
                    .contains(&RuleAttribute::Table(ROUTE_LOCAL_TABLE_ID))
            {
                let priority = rule.attributes.iter().find_map(|attr| {
                    if let &RuleAttribute::Priority(num) = attr {
                        Some(num)
                    } else {
                        None
                    }
                });
                let priority = priority.unwrap_or(0);
                res.push((rule, priority));
            }
        }

        Ok(res)
    }

    async fn deprioritize_local_ip_rule(&self, is_ipv4: bool) -> Result<()> {
        let local_rules = self.local_ip_rules(is_ipv4).await?;
        if local_rules
            .iter()
            .all(|(_rule, priority)| *priority == LOCAL_RULE_PRIORITY)
        {
            return Ok(());
        }

        let mut add_local_rule = self
            .handle
            .rule()
            .add()
            .action(RuleAction::ToTable)
            .table_id(ROUTE_LOCAL_TABLE_ID)
            .priority(LOCAL_RULE_PRIORITY);

        add_local_rule.message_mut().header.family = if is_ipv4 {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };

        // Add protocol=kernel to prevent it from being deleted by systemd-networkd
        // in case `ManageForeignRoutingPolicyRules` was not disabled.
        add_local_rule
            .message_mut()
            .attributes
            .push(RuleAttribute::Protocol(RouteProtocol::Kernel));

        if let Err(e) = add_local_rule.execute().await {
            if !route_err_is_exist(&e) {
                return Err(anyhow::anyhow!(e));
            }
            eprintln!("exist");
        }

        for (rule, priority) in local_rules {
            if priority < LOCAL_RULE_PRIORITY {
                self.handle.rule().del(rule).execute().await?;
            }
        }

        Ok(())
    }
}

pub enum MonitorEvent {
    ChangeAddress { if_index: u32 },
}

pub trait RouteIpNetwork: IpNetwork + Copy + Eq {
    const FAMILY: AddressFamily;
    const IP_VERSION: IpVersion;
    const IS_IPV4: bool;

    fn route_add_set_dest(
        &self,
        req: RouteAddRequest<()>,
        gateway: &Self,
    ) -> RouteAddRequest<Self::Addr>;

    fn neigh_add(&self, if_index: u32, handle: &Handle) -> NeighbourAddRequest;

    fn from_route_address(address: &RouteAddress, prefix_len: u8) -> Option<Self>;
}

impl RouteIpNetwork for Ipv4Net {
    const FAMILY: AddressFamily = AddressFamily::Inet;
    const IP_VERSION: IpVersion = IpVersion::V4;
    const IS_IPV4: bool = true;

    fn route_add_set_dest(
        &self,
        req: RouteAddRequest<()>,
        gateway: &Self,
    ) -> RouteAddRequest<Self::Addr> {
        let req = req.v4().destination_prefix(self.addr(), self.prefix_len());
        if gateway == self {
            req
        } else {
            req.gateway(gateway.addr())
        }
    }

    fn neigh_add(&self, if_index: u32, handle: &Handle) -> NeighbourAddRequest {
        handle.neighbours().add(if_index, IpAddr::V4(self.addr()))
    }

    fn from_route_address(address: &RouteAddress, prefix_len: u8) -> Option<Self> {
        if prefix_len > Self::LEN {
            return None;
        }
        if let RouteAddress::Inet(v4) = address {
            Some(Ipv4Net::new(*v4, prefix_len).unwrap())
        } else {
            None
        }
    }
}

#[cfg(feature = "ipv6")]
impl RouteIpNetwork for Ipv6Net {
    const FAMILY: AddressFamily = AddressFamily::Inet6;
    const IP_VERSION: IpVersion = IpVersion::V6;
    const IS_IPV4: bool = false;

    fn route_add_set_dest(
        &self,
        req: RouteAddRequest<()>,
        gateway: &Self,
    ) -> RouteAddRequest<Self::Addr> {
        let req = req.v6().destination_prefix(self.addr(), self.prefix_len());
        if gateway == self {
            req
        } else {
            req.gateway(gateway.addr())
        }
    }

    fn neigh_add(&self, if_index: u32, handle: &Handle) -> NeighbourAddRequest {
        handle.neighbours().add(if_index, IpAddr::V6(self.addr()))
    }

    fn from_route_address(address: &RouteAddress, prefix_len: u8) -> Option<Self> {
        if prefix_len > Self::LEN {
            return None;
        }
        if let RouteAddress::Inet6(v6) = address {
            Some(Ipv6Net::new(*v6, prefix_len).unwrap())
        } else {
            None
        }
    }
}

struct RouteDescriber<N> {
    destination: N,
    output_if_index: u32,
    table_id: u32,
}

impl<N: RouteIpNetwork> RouteDescriber<N> {
    fn matches(&self, route: &RouteMessage) -> bool {
        Some(self.destination) == route_destination(route)
            && self.table_id == route_table_id(route)
            && Some(self.output_if_index) == route_output_if_index(route)
    }
}

pub struct HairpinRouting<N> {
    rt_helper: RouteHelper,
    external_if_index: u32,
    table_id: u32,
    gateway_neigh: Option<(N, NeighbourMessage)>,
    hairpin_dests: Vec<N>,
    rules: Vec<RuleMessage>,
    routes: Vec<RouteDescriber<N>>,
}

impl<N: RouteIpNetwork> HairpinRouting<N> {
    pub fn new(rt_helper: RouteHelper, external_if_index: u32, table_id: u32) -> Self {
        Self {
            rt_helper,
            external_if_index,
            table_id,
            gateway_neigh: Default::default(),
            hairpin_dests: Default::default(),
            rules: Default::default(),
            routes: Default::default(),
        }
    }

    fn handle(&self) -> &Handle {
        &self.rt_helper.handle
    }

    async fn configure_(
        &mut self,
        mut internal_if_names: Vec<String>,
        mut ip_protocols: Vec<IpProtocol>,
        hairpin_dests: Vec<N>,
    ) -> Result<()> {
        assert!(
            self.gateway_neigh.is_none() && self.rules.is_empty() && self.hairpin_dests.is_empty()
        );

        self.reconfigure_dests(hairpin_dests).await?;

        internal_if_names.dedup();
        if !internal_if_names.is_empty() {
            self.rt_helper
                .deprioritize_local_ip_rule(N::IS_IPV4)
                .await?;
        }

        ip_protocols.dedup();
        for iif_name in internal_if_names {
            for &protocol in ip_protocols.iter() {
                self.add_rule(&iif_name, protocol.into()).await?;
            }
        }

        Ok(())
    }

    pub async fn configure(
        &mut self,
        internal_if_names: Vec<String>,
        ip_protocols: Vec<IpProtocol>,
        hairpin_dests: Vec<N>,
    ) -> Result<()> {
        let res = self
            .configure_(internal_if_names, ip_protocols, hairpin_dests)
            .await;
        if res.is_err() {
            let _ = self.deconfigure().await;
        }
        res
    }

    async fn add_route(&mut self, dest: N) -> Result<()> {
        let (gateway, _) = self.gateway_neigh.as_ref().expect("no gateway");

        let req = self
            .handle()
            .route()
            .add()
            .table_id(self.table_id)
            .output_interface(self.external_if_index);

        dest.route_add_set_dest(req, gateway).execute().await?;

        self.routes.push(RouteDescriber {
            destination: dest,
            output_if_index: self.external_if_index,
            table_id: self.table_id,
        });

        Ok(())
    }

    async fn del_all_route(&mut self) -> Result<()> {
        let mut s = self.handle().route().get(N::IP_VERSION).execute();
        while let Some(route) = s.try_next().await? {
            if self
                .routes
                .iter()
                .any(|describer| describer.matches(&route))
            {
                if let Err(e) = self.handle().route().del(route).execute().await {
                    eprintln!("failed to delete route: {}", e);
                }
            }
        }
        self.routes.clear();
        Ok(())
    }

    async fn add_rule(&mut self, iif_name: &str, ip_protocol: RouteIpProtocol) -> Result<()> {
        let mut req = self
            .handle()
            .rule()
            .add()
            .input_interface(iif_name.to_string())
            .table_id(self.table_id)
            .priority(HAIRPIN_RULE_PRIORITY)
            .action(RuleAction::ToTable);
        req.message_mut().header.family = N::FAMILY;
        req.message_mut()
            .attributes
            .push(RuleAttribute::IpProtocol(ip_protocol));

        let rule = req.message_mut().clone();

        if let Err(e) = req.execute().await {
            if !route_err_is_exist(&e) {
                return Err(anyhow::anyhow!(e));
            }
        }

        self.rules.push(rule);

        Ok(())
    }

    async fn del_neigh(&mut self) {
        if let Some((_, neigh)) = self.gateway_neigh.take() {
            if let Err(e) = self.handle().neighbours().del(neigh).execute().await {
                eprintln!("failed to delete neigh entry: {}", e);
            }
        }
    }

    pub async fn reconfigure_neigh(&mut self, gateway: Option<N>) -> Result<()> {
        let prev_gateway = self.gateway_neigh.as_ref().map(|(gateway, _)| *gateway);
        if prev_gateway == gateway {
            return Ok(());
        }

        self.del_neigh().await;

        let Some(gateway) = gateway else {
            return Ok(());
        };

        let external_link = self
            .handle()
            .link()
            .get()
            .match_index(self.external_if_index)
            .execute()
            .try_next()
            .await?;
        let Some(external_link) = external_link else {
            return Err(anyhow::anyhow!(
                "external interface {} not exist",
                self.external_if_index
            ));
        };
        let ll_addr = external_link.attributes.into_iter().find_map(|attr| {
            if let LinkAttribute::Address(addr) = attr {
                Some(addr)
            } else {
                None
            }
        });
        let Some(ll_addr) = ll_addr else {
            return Err(anyhow::anyhow!(
                "external interface {} has no link local address",
                self.external_if_index
            ));
        };

        let mut req = gateway
            .neigh_add(self.external_if_index, self.handle())
            .link_local_address(&ll_addr)
            .replace()
            .state(NeighbourState::Permanent);
        let neigh = req.message_mut().clone();

        req.execute().await?;

        self.gateway_neigh = Some((gateway, neigh));

        Ok(())
    }

    async fn reconfigure_dests_(&mut self, hairpin_dests: Vec<N>) -> Result<()> {
        self.del_all_route().await?;
        self.reconfigure_neigh(hairpin_dests.first().copied())
            .await?;

        for dest in hairpin_dests {
            self.add_route(dest).await?;
        }

        Ok(())
    }

    pub async fn reconfigure_dests(&mut self, hairpin_dests: Vec<N>) -> Result<()> {
        let res = self.reconfigure_dests_(hairpin_dests).await;
        if res.is_err() {
            let _ = self.deconfigure().await;
        }
        res
    }

    pub async fn deconfigure(&mut self) -> Result<()> {
        for rule in core::mem::take(&mut self.rules) {
            let _ = self.handle().rule().del(rule).execute().await;
        }
        let _ = self.del_all_route().await;

        self.del_neigh().await;
        Ok(())
    }
}

/// This must be called from Tokio context.
pub fn spawn_monitor() -> Result<(
    JoinHandle<()>,
    RouteHelper,
    impl Stream<Item = MonitorEvent>,
)> {
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

    Ok((task, RouteHelper { handle }, events))
}

fn route_err_is_exist(e: &rtnetlink::Error) -> bool {
    if let rtnetlink::Error::NetlinkError(e) = e {
        if let Some(code) = e.code {
            if code.get() == -libc::EEXIST {
                return true;
            }
        }
    }
    false
}

fn route_destination<N: RouteIpNetwork>(route: &RouteMessage) -> Option<N> {
    let dest = route.attributes.iter().find_map(|attr| {
        if let RouteAttribute::Destination(dest) = attr {
            Some(dest)
        } else {
            None
        }
    });
    if let Some(dest) = dest {
        N::from_route_address(dest, route.header.destination_prefix_length)
    } else {
        None
    }
}

fn route_output_if_index(route: &RouteMessage) -> Option<u32> {
    route.attributes.iter().find_map(|attr| {
        if let RouteAttribute::Oif(oif) = attr {
            Some(*oif)
        } else {
            None
        }
    })
}

fn route_table_id(route: &RouteMessage) -> u32 {
    let table_id = route.attributes.iter().find_map(|attr| {
        if let RouteAttribute::Table(table_id) = attr {
            Some(*table_id)
        } else {
            None
        }
    });
    table_id.unwrap_or(route.header.table as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_async_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn get_addr() {
        new_async_rt().block_on(async {
            let (_, rt_helper, _) = spawn_monitor().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                rt_helper.query_all_addresses(1).await.unwrap();
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn get_local_rule() {
        new_async_rt().block_on(async {
            let (_, rt_helper, _) = spawn_monitor().unwrap();
            let rules = rt_helper.local_ip_rules(true).await.unwrap();
            dbg!(rules);
        })
    }

    #[test]
    fn get_routes() {
        new_async_rt().block_on(async {
            let (_, rt_helper, _) = spawn_monitor().unwrap();
            let req = rt_helper.handle.route().get(IpVersion::V4);
            let mut routes = req.execute();
            while let Some(route) = routes.try_next().await.unwrap() {
                dbg!(route);
            }
        })
    }
}
