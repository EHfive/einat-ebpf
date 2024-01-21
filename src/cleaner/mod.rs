mod route;

use std::pin::pin;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use futures_util::StreamExt;

use crate::skel::FullConeNatSkel;

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
                ext_addr: _,
                dest_addr: _,
                ext_port: _,
                dest_port: _,
            } = tuple;

            // TODO: delete binding and CT from maps
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
            fn drop(&mut self) {}
        }

        let skel = PausingRecover(skel);
        let _maps = skel.0.maps();

        // TODO: filter map entries to be deleted
    }

    drop(tx);
    clean_task.await?;
    Ok(())
}
