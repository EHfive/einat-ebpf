// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(feature = "aya")]
mod aya;
#[cfg(any(feature = "libbpf", feature = "libbpf-skel"))]
mod libbpf;

pub mod einat;

use std::borrow::BorrowMut;

use anyhow::Result;
use bitflags::bitflags;

pub use einat::types::*;

use crate::utils::IpNetwork;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    #[repr(transparent)]
    pub struct EbpfMapFlags: u64 {
        const ANY = 0;
        const NO_EXIST = 0b1;
        const EXIST = 0b10;
        const F_LOCK = 0b100;
    }
}

pub trait EbpfHashMap<K, V> {
    type BorrowK: BorrowMut<K>;
    type BorrowV: BorrowMut<V>;

    fn keys(&self) -> impl Iterator<Item = Result<Self::BorrowK>>;

    fn lookup(&self, k: &K, flags: EbpfMapFlags) -> Result<Option<Self::BorrowV>>;
}

pub trait EbpfHashMapMut<K: 'static, V>: EbpfHashMap<K, V> {
    #[allow(unused)]
    fn update(&mut self, k: &K, v: &V, flags: EbpfMapFlags) -> Result<()>;

    #[allow(unused)]
    fn delete(&mut self, k: &K) -> Result<()>;

    fn delete_batch<'i>(
        &mut self,
        keys: impl IntoIterator<Item = &'i K>,
        elem_flags: EbpfMapFlags,
    ) -> Result<()>;
}

pub trait EbpfLpmTrie<K: IpNetwork, V> {
    type BorrowV: BorrowMut<V>;

    #[allow(unused)]
    fn lookup(&self, k: &K, flags: EbpfMapFlags) -> Result<Option<Self::BorrowV>>;
}

pub trait EbpfLpmTrieMut<K: IpNetwork, V>: EbpfLpmTrie<K, V> {
    fn update(&mut self, k: &K, v: &V, flags: EbpfMapFlags) -> Result<()>;

    fn delete(&mut self, k: &K) -> Result<()>;
}
