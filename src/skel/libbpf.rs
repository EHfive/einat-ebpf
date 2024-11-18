// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

use std::borrow::{Borrow, BorrowMut};
use std::fmt::Debug;
use std::mem;

use anyhow::Result;
use bytemuck::{Pod, Zeroable};
use libbpf_rs::{MapCore, MapFlags};

use super::{EbpfHashMap, EbpfHashMapMut, EbpfLpmTrie, EbpfLpmTrieMut, EbpfMapFlags};
use crate::utils::{IpAddress, IpNetwork};

pub struct LibbpfMap<T: MapCore>(pub(super) T);

pub struct ValueVec(Vec<u8>);

impl<V: Pod> Borrow<V> for ValueVec {
    fn borrow(&self) -> &V {
        bytemuck::from_bytes(&self.0)
    }
}

impl<V: Pod> BorrowMut<V> for ValueVec {
    fn borrow_mut(&mut self) -> &mut V {
        bytemuck::from_bytes_mut(&mut self.0)
    }
}

impl From<EbpfMapFlags> for MapFlags {
    fn from(value: EbpfMapFlags) -> Self {
        Self::from_bits_retain(value.bits())
    }
}

impl<K: Pod, V: Pod, T: MapCore> EbpfHashMap<K, V> for LibbpfMap<T> {
    type BorrowK = ValueVec;
    type BorrowV = ValueVec;

    fn keys(&self) -> impl Iterator<Item = Result<Self::BorrowK>> {
        MapCore::keys(&self.0).map(|item| Ok(ValueVec(item)))
    }

    fn lookup(&self, k: &K, flags: EbpfMapFlags) -> Result<Option<Self::BorrowV>> {
        let v = MapCore::lookup(&self.0, bytemuck::bytes_of(k), Into::into(flags))?.map(ValueVec);
        Ok(v)
    }
}

impl<K: Pod, V: Pod, T: MapCore> EbpfHashMapMut<K, V> for LibbpfMap<T> {
    fn update(&mut self, k: &K, v: &V, flags: EbpfMapFlags) -> Result<()> {
        MapCore::update(
            &self.0,
            bytemuck::bytes_of(k),
            bytemuck::bytes_of(v),
            Into::into(flags),
        )?;
        Ok(())
    }

    fn delete(&mut self, k: &K) -> Result<()> {
        MapCore::delete(&self.0, bytemuck::bytes_of(k))?;
        Ok(())
    }

    fn delete_batch<'i>(
        &mut self,
        keys: impl IntoIterator<Item = &'i K>,
        elem_flags: EbpfMapFlags,
    ) -> Result<()> {
        let mut keys_raw = Vec::new();
        for key in keys {
            keys_raw.extend(bytemuck::bytes_of(key));
        }
        let count = (keys_raw.len() / mem::size_of::<K>()) as u32;

        MapCore::delete_batch(
            &self.0,
            &keys_raw,
            count,
            Into::into(elem_flags),
            MapFlags::ANY,
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Zeroable, Pod)]
#[repr(C, packed)]
struct LpmKey<K> {
    pub prefix_len: u32,
    pub data: K,
}

impl<T: IpNetwork> From<&T> for LpmKey<<T::Addr as IpAddress>::Data> {
    fn from(value: &T) -> Self {
        Self {
            prefix_len: value.prefix_len() as _,
            data: value.addr().data(),
        }
    }
}

impl<K: IpNetwork, V: Pod, T: MapCore> EbpfLpmTrie<K, V> for LibbpfMap<T>
where
    <K::Addr as IpAddress>::Data: Pod,
{
    type BorrowV = ValueVec;

    fn lookup(&self, k: &K, flags: EbpfMapFlags) -> Result<Option<Self::BorrowV>> {
        let k = &LpmKey::from(k);
        let v = MapCore::lookup(&self.0, bytemuck::bytes_of(k), Into::into(flags))?.map(ValueVec);
        Ok(v)
    }
}

impl<K: IpNetwork, V: Pod, T: MapCore> EbpfLpmTrieMut<K, V> for LibbpfMap<T>
where
    <K::Addr as IpAddress>::Data: Pod,
{
    fn update(&mut self, k: &K, v: &V, flags: EbpfMapFlags) -> Result<()> {
        let k = &LpmKey::from(k);
        MapCore::update(
            &self.0,
            bytemuck::bytes_of(k),
            bytemuck::bytes_of(v),
            Into::into(flags),
        )?;
        Ok(())
    }

    fn delete(&mut self, k: &K) -> Result<()> {
        let k = &LpmKey::from(k);
        MapCore::delete(&self.0, bytemuck::bytes_of(k))?;
        Ok(())
    }
}
