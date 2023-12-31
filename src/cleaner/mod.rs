mod conntrack;
mod route;

use std::pin::pin;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use futures_util::StreamExt;

use crate::skel::{ConnKey, FullConeNatSkel};

fn ip_addr_from_slice(bytes: &[u8; 16], is_ipv4: bool) -> IpAddr {
    if is_ipv4 {
        let bytes: &[u8; 4] = bytes[..4].try_into().unwrap();
        IpAddr::V4(Ipv4Addr::from(*bytes))
    } else {
        IpAddr::V6(Ipv6Addr::from(*bytes))
    }
}

#[derive(Debug)]
struct ConnTuple {
    ext_addr: IpAddr,
    dest_addr: IpAddr,
    ext_port: u16,
    dest_port: u16,
}

pub async fn clean_ct_task(
    skel: &mut FullConeNatSkel<'_>,
    if_index: u32,
) -> Result<(), Box<dyn Error>> {
    let mut stream = pin!(route::subscribe_interface_event()?);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ConnTuple>(4096);
    let clean_task = tokio::spawn(async move {
        while let Some(tuple) = rx.recv().await {
            let ConnTuple {
                ext_addr,
                dest_addr,
                ext_port,
                dest_port,
            } = tuple;

            // It's external IP being changed so we filter by that to avoid deleting valid conntrack
            if let Err(_e) =
                conntrack::delete_udp_ct(true, dest_addr, ext_addr, dest_port, ext_port).await
            {
                // CTs could already be deleted by nf_nat so it's expected to error

                // println!(
                //     "failed to delete {}:{}({}:{}) -> {}:{}, err: {:?}",
                //     ext_addr, ext_port, src_addr, src_port, dest_addr, dest_port, e
                // );
            }
        }
    });

    while let Some(ev) = stream.next().await {
        let ev = match ev {
            Ok(ev) => ev,
            Err(e) => {
                // could be a paring error, ignore
                eprintln!("{:?}", e);
                continue;
            }
        };
        if ev.if_index != if_index {
            continue;
        }

        struct PausingRecover<'a, 'b>(&'a mut FullConeNatSkel<'b>);
        impl Drop for PausingRecover<'_, '_> {
            fn drop(&mut self) {
                self.0.data_mut().pausing = false;
            }
        }

        let skel = PausingRecover(skel);
        skel.0.data_mut().pausing = true;
        let maps = skel.0.maps();

        for key in maps.conn_table().keys() {
            let conn_key: &ConnKey = bytemuck::from_bytes(&key);
            if conn_key.mapping_key.if_index != if_index {
                continue;
            }
            let is_ipv4 = conn_key.mapping_key.is_ipv4 != 0;
            let ext_addr = ip_addr_from_slice(&conn_key.mapping_key.ext_addr, is_ipv4);
            if let Some(addr) = ev.ip_addr {
                if addr != ext_addr {
                    continue;
                }
            }
            // let src_addr = ip_addr_from_slice(&conn_key.origin.src_addr, is_ipv4);
            let dest_addr = ip_addr_from_slice(&conn_key.origin.dst_addr, is_ipv4);
            // let src_port = u16::from_be(conn_key.origin.src_port);
            let dest_port = u16::from_be(conn_key.origin.dst_port);
            let ext_port = u16::from_be(conn_key.mapping_key.ext_port);

            tx.send(ConnTuple {
                ext_addr,
                dest_addr,
                ext_port,
                dest_port,
            })
            .await?;
        }
    }

    drop(tx);
    clean_task.await?;
    Ok(())
}
