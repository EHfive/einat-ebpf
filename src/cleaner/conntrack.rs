use std::{error::Error, net::IpAddr};

use neli::{
    consts::{nl::*, socket::*},
    genl::{AttrType, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder, NoUserHeader},
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    socket::asynchronous::NlSocketHandle,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;

const IPCTNL_MSG_CT_DELETE: u8 = 2;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;

const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

const IPPROTO_UDP: u8 = 17;

type NfNlEnum = u16;
type CtL3Proto = u8;
type CtAttrEnum = u16;
type CtAttr = AttrType<CtAttrEnum>;
type NfNlmsghr = Genlmsghdr<CtL3Proto, CtAttrEnum, NoUserHeader>;

#[inline]
const fn subsys_message(subsys: u8, msg: u8) -> NfNlEnum {
    ((subsys as u16) << 8) | (msg as u16)
}

fn build_delete_udp_ct_msg(
    is_reply: bool,
    s_addr: IpAddr,
    d_addr: IpAddr,
    s_port: u16,
    d_port: u16,
) -> Result<Nlmsghdr<NfNlEnum, NfNlmsghr>, Box<dyn Error>> {
    let is_ipv4 = matches!(s_addr, IpAddr::V4(_));
    if is_ipv4 != matches!(d_addr, IpAddr::V4(_)) {
        return Err("not same IP version".into());
    }

    let mut buf = GenlBuffer::<u16, Buffer>::new();

    let cta_tuple_ip = {
        let (attr, data) = match s_addr {
            IpAddr::V4(v4) => (CTA_IP_V4_SRC, v4.octets().to_vec()),
            IpAddr::V6(v6) => (CTA_IP_V6_SRC, v6.octets().to_vec()),
        };
        let cta_ip_v4_src = NlattrBuilder::default()
            .nla_type(CtAttr::from(attr))
            .nla_payload(Buffer::from(data))
            .build()?;

        let (attr, data) = match d_addr {
            IpAddr::V4(v4) => (CTA_IP_V4_DST, v4.octets().to_vec()),
            IpAddr::V6(v6) => (CTA_IP_V6_DST, v6.octets().to_vec()),
        };
        let cta_ip_v4_dst = NlattrBuilder::default()
            .nla_type(CtAttr::from(attr))
            .nla_payload(Buffer::from(data))
            .build()?;

        NlattrBuilder::default()
            .nla_type(CtAttr::from(CTA_TUPLE_IP))
            .nla_payload(Buffer::new())
            .build()?
            .nest(&cta_ip_v4_src)?
            .nest(&cta_ip_v4_dst)?
    };

    let cta_tuple_proto = {
        let cta_proto_num = NlattrBuilder::default()
            .nla_type(CtAttr::from(CTA_PROTO_NUM))
            .nla_payload(Buffer::from(vec![IPPROTO_UDP]))
            .build()?;
        let cta_proto_src_port = NlattrBuilder::default()
            .nla_type(CtAttr::from(CTA_PROTO_SRC_PORT))
            .nla_payload(Buffer::from(s_port.to_be_bytes().to_vec()))
            .build()?;
        let cta_proto_dst_port = NlattrBuilder::default()
            .nla_type(CtAttr::from(CTA_PROTO_DST_PORT))
            .nla_payload(Buffer::from(d_port.to_be_bytes().to_vec()))
            .build()?;
        NlattrBuilder::default()
            .nla_type(CtAttr::from(CTA_TUPLE_PROTO))
            .nla_payload(Buffer::new())
            .build()?
            .nest(&cta_proto_num)?
            .nest(&cta_proto_src_port)?
            .nest(&cta_proto_dst_port)?
    };

    let nla_type = if is_reply {
        CTA_TUPLE_REPLY
    } else {
        CTA_TUPLE_ORIG
    };
    let cta_tuple = NlattrBuilder::default()
        .nla_type(CtAttr::from(nla_type))
        .nla_payload(Buffer::new())
        .build()?
        .nest(&cta_tuple_ip)?
        .nest(&cta_tuple_proto)?;

    buf.push(cta_tuple);

    let l3proto = if is_ipv4 { NFPROTO_IPV4 } else { NFPROTO_IPV6 };
    let genl_msg = GenlmsghdrBuilder::<CtL3Proto, _, _>::default()
        .cmd(l3proto)
        .version(libc::NFNETLINK_V0 as u8)
        .attrs(buf)
        .build()?;

    let nl_msg = NlmsghdrBuilder::<NfNlEnum, _>::default()
        .nl_type(subsys_message(
            libc::NFNL_SUBSYS_CTNETLINK as _,
            IPCTNL_MSG_CT_DELETE,
        ))
        .nl_payload(NlPayload::Payload(genl_msg))
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .build()?;

    Ok(nl_msg)
}

pub async fn delete_udp_ct(
    is_reply: bool,
    s_addr: IpAddr,
    d_addr: IpAddr,
    s_port: u16,
    d_port: u16,
) -> Result<(), Box<dyn Error>> {
    let s = NlSocketHandle::connect(NlFamily::Netfilter, None, Groups::empty())?;
    let nl_msg = build_delete_udp_ct_msg(is_reply, s_addr, d_addr, s_port, d_port)?;
    s.send(&nl_msg).await?;

    let (msgs, _) = s.recv::<CtAttrEnum, NfNlmsghr>().await?;
    for res in msgs {
        let mut res: Nlmsghdr<NfNlEnum, NfNlmsghr> = res?;
        if let Some(err) = res.get_err() {
            return Err(err.into());
        }
    }
    Ok(())
}
