use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use async_stream::try_stream;
use futures_util::Stream;
use neli::{
    consts::{rtnl::*, socket::*},
    nl::*,
    rtnl::*,
    socket::asynchronous::NlSocketHandle,
    utils::Groups,
};

pub struct IfDownEvent {
    pub if_index: u32,
    pub ip_addr: Option<IpAddr>,
}

type StreamItem = Result<IfDownEvent, Box<dyn Error>>;

pub fn subscribe_interface_event() -> Result<impl Stream<Item = StreamItem>, Box<dyn Error>> {
    let s_link = NlSocketHandle::connect(
        NlFamily::Route,
        None,
        Groups::new_groups(&[
            libc::RTNLGRP_LINK,
            libc::RTNLGRP_IPV4_IFADDR,
            libc::RTNLGRP_IPV6_IFADDR,
        ]),
    )?;

    fn cvt_link_msg(msg: Nlmsghdr<Rtm, Ifinfomsg>) -> Option<IfDownEvent> {
        let link_msg = msg.get_payload()?;
        match msg.nl_type() {
            Rtm::Newlink => {
                let up_changed = link_msg.ifi_change().contains(Iff::UP);
                let is_up = link_msg.ifi_flags().contains(Iff::UP);
                if !up_changed || is_up {
                    return None;
                }
            }
            Rtm::Dellink => {}
            _ => return None,
        }

        eprintln!(
            "{:?} ifindex:{} flags:{:?} change:{:?}",
            msg.nl_type(),
            link_msg.ifi_index(),
            link_msg.ifi_flags(),
            link_msg.ifi_change(),
        );
        Some(IfDownEvent {
            if_index: *link_msg.ifi_index() as _,
            ip_addr: None,
        })
    }

    fn cvt_addr_msg(msg: Nlmsghdr<Rtm, Ifaddrmsg>) -> Option<IfDownEvent> {
        let addr_msg = msg.get_payload()?;

        if !matches!(msg.nl_type(), Rtm::Deladdr) {
            return None;
        }

        let rt_attrs_handle = addr_msg.rtattrs().get_attr_handle();
        let addr_attr = rt_attrs_handle.get_attribute(Ifa::Address)?;

        let bytes: &[u8] = addr_attr.rta_payload().as_ref();
        let ip_addr = if bytes.len() == 4 {
            let bytes: &[u8; 4] = bytes.try_into().unwrap();
            IpAddr::V4(Ipv4Addr::from(*bytes))
        } else if bytes.len() == 16 {
            let bytes: &[u8; 16] = bytes.try_into().unwrap();
            IpAddr::V6(Ipv6Addr::from(*bytes))
        } else {
            return None;
        };

        println!(
            "{:?} ifindex:{} {:?}",
            msg.nl_type(),
            addr_msg.ifa_index(),
            ip_addr
        );
        Some(IfDownEvent {
            if_index: *addr_msg.ifa_index() as _,
            ip_addr: Some(ip_addr),
        })
    }

    let s = try_stream! {
        loop {
            let (mut msgs, groups) = s_link.recv::<Rtm, Ifinfomsg>().await?;
            if groups.as_bitmask() == libc::RTMGRP_LINK as u32 {
                while let Some(msg) = msgs.next_typed::<Rtm, Ifinfomsg>() {
                    if let Some(ev) = cvt_link_msg(msg?) {
                        yield ev;
                    }
                }
            } else {
                while let Some(msg) = msgs.next_typed::<Rtm, Ifaddrmsg>() {
                    if let Some(ev) = cvt_addr_msg(msg?) {
                        yield ev;
                    }
                }
            }
        }
    };
    Ok(s)
}
