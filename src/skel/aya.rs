// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

use std::borrow::BorrowMut;
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

pub use ::aya::maps::{HashMap, LpmTrie};
use anyhow::{anyhow, Result};
use aya::maps::{lpm_trie::Key, IterableMap, MapData, MapError};
use aya_obj::generated::{bpf_attr, bpf_cmd};

use super::{EbpfHashMap, EbpfHashMapMut, EbpfLpmTrie, EbpfLpmTrieMut, EbpfMapFlags};
use crate::utils::{IpAddress, IpNetwork};

/// 'alias' trait for bytemuck::Pod + aya::Pod
trait Pod: bytemuck::Pod + aya::Pod {}
impl<T: bytemuck::Pod + aya::Pod> Pod for T {}

unsafe fn map_delete_batch(
    map_fd: BorrowedFd<'_>,
    keys_raw: &[u8],
    count: u32,
    elem_flags: u64,
) -> Result<()> {
    let mut attr = mem::zeroed::<bpf_attr>();
    let batch = &mut attr.batch;

    batch.keys = keys_raw.as_ptr() as _;
    batch.count = count;
    batch.map_fd = map_fd.as_raw_fd() as _;
    batch.elem_flags = elem_flags;

    let ret = libc::syscall(
        libc::SYS_bpf,
        bpf_cmd::BPF_MAP_DELETE_BATCH,
        &mut attr,
        mem::size_of::<bpf_attr>(),
    );
    if ret < 0 {
        return Err(anyhow!(io::Error::last_os_error())
            .context(format!("bpf(BPF_MAP_DELETE_BATCH) failed with {}", ret)));
    }

    // we don't want a partial deletion of batch
    assert_eq!(count, attr.batch.count);
    Ok(())
}

impl<T, K: Pod, V: Pod> EbpfHashMap<K, V> for HashMap<T, K, V>
where
    T: BorrowMut<MapData>,
{
    type BorrowK = K;
    type BorrowV = V;

    fn keys(&self) -> impl Iterator<Item = Result<Self::BorrowK>> {
        self.keys().map(|res| match res {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into()),
        })
    }

    fn lookup(&self, k: &K, flags: EbpfMapFlags) -> Result<Option<Self::BorrowV>> {
        let res = self.get(k, flags.bits());
        let v = match res {
            Ok(v) => Some(v),
            Err(MapError::KeyNotFound) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(v)
    }
}

impl<T, K: Pod, V: Pod> EbpfHashMapMut<K, V> for HashMap<T, K, V>
where
    T: BorrowMut<MapData>,
{
    fn update(&mut self, k: &K, v: &V, flags: EbpfMapFlags) -> Result<()> {
        self.insert(k, v, flags.bits())?;
        Ok(())
    }

    fn delete(&mut self, k: &K) -> Result<()> {
        self.remove(k)?;
        Ok(())
    }

    fn delete_batch<'i>(
        &mut self,
        keys: impl IntoIterator<Item = &'i K>,
        elem_flags: EbpfMapFlags,
    ) -> Result<()> {
        let mut keys_raw = Vec::<u8>::new();
        for key in keys {
            keys_raw.extend(bytemuck::bytes_of(key));
        }
        let count = (keys_raw.len() / mem::size_of::<K>()) as u32;

        if count == 0 {
            return Ok(());
        }

        let map_fd = self.map().fd().as_fd();

        unsafe { map_delete_batch(map_fd, &keys_raw, count, elem_flags.bits()) }
    }
}

fn key_from_ip_net<K: IpNetwork>(network: &K) -> Key<<K::Addr as IpAddress>::Data>
where
    <K::Addr as IpAddress>::Data: Pod,
{
    Key::new(network.prefix_len() as _, network.addr().data())
}

impl<T, K: IpNetwork, V: Pod> EbpfLpmTrie<K, V> for LpmTrie<T, <K::Addr as IpAddress>::Data, V>
where
    T: BorrowMut<MapData>,
    <K::Addr as IpAddress>::Data: Pod,
{
    type BorrowV = V;

    fn lookup(&self, k: &K, flags: EbpfMapFlags) -> Result<Option<Self::BorrowV>> {
        let res = self.get(&key_from_ip_net(k), flags.bits());
        let v = match res {
            Ok(v) => Some(v),
            Err(MapError::KeyNotFound) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(v)
    }
}

impl<T, K: IpNetwork, V: Pod> EbpfLpmTrieMut<K, V> for LpmTrie<T, <K::Addr as IpAddress>::Data, V>
where
    T: BorrowMut<MapData>,
    <K::Addr as IpAddress>::Data: Pod,
{
    fn update(&mut self, k: &K, v: &V, flags: EbpfMapFlags) -> Result<()> {
        self.insert(&key_from_ip_net(k), v, flags.bits())?;
        Ok(())
    }

    fn delete(&mut self, k: &K) -> Result<()> {
        self.remove(&key_from_ip_net(k))?;
        Ok(())
    }
}
