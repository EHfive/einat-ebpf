// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//! Model for configuration variables and maps of our eBPF application
use std::iter::Iterator;
use std::net::Ipv4Addr;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;

use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use prefix_trie::{map::Iter as PrefixMapIter, Prefix, PrefixMap};

pub enum MapChange<'a, P, T> {
    Insert(&'a P, &'a T),
    Update(&'a P, &'a T),
    Delete(&'a P),
}

pub struct PrefixMapDiff<'a, P, T> {
    map_a: &'a PrefixMap<P, T>,
    map_b: &'a PrefixMap<P, T>,
    map_a_iter: PrefixMapIter<'a, P, T>,
    map_b_iter: PrefixMapIter<'a, P, T>,
    map_a_finished: bool,
}

impl<'a, P, T> PrefixMapDiff<'a, P, T> {
    pub fn new(map_a: &'a PrefixMap<P, T>, map_b: &'a PrefixMap<P, T>) -> Self {
        Self {
            map_a,
            map_b,
            map_a_iter: map_a.iter(),
            map_b_iter: map_b.iter(),
            map_a_finished: false,
        }
    }
}
impl<'a, P, T> Iterator for PrefixMapDiff<'a, P, T>
where
    P: Prefix,
    T: PartialEq,
{
    type Item = MapChange<'a, P, T>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.map_a_finished {
            for (key, value) in self.map_a_iter.by_ref() {
                if let Some(other_value) = self.map_b.get(key) {
                    if other_value != value {
                        return Some(MapChange::Update(key, other_value));
                    }
                } else {
                    return Some(MapChange::Delete(key));
                }
            }
            self.map_a_finished = true
        }

        for (key, value) in self.map_b_iter.by_ref() {
            if self.map_a.get(key).is_none() {
                return Some(MapChange::Insert(key, value));
            }
        }

        None
    }
}

pub fn ipv4_addr_to_net(address: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(address, 32).unwrap()
}

#[cfg(feature = "ipv6")]
pub fn ipv6_addr_to_net(address: Ipv6Addr) -> Ipv6Net {
    Ipv6Net::new(address, 128).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;

    #[test]
    fn map_diff() {
        let mut map_a = PrefixMap::<Ipv4Net, String>::new();
        let mut map_b = PrefixMap::<Ipv4Net, String>::new();

        map_a.insert("192.168.0.0/24".parse().unwrap(), "to delete".to_string());
        map_a.insert("192.168.0.0/25".parse().unwrap(), "unchanged".to_string());
        map_a.insert("192.168.0.0/26".parse().unwrap(), "before".to_string());

        map_b.insert("192.168.0.0/25".parse().unwrap(), "unchanged".to_string());
        map_b.insert("192.168.0.0/26".parse().unwrap(), "to update".to_string());
        map_b.insert("192.168.0.0/27".parse().unwrap(), "to insert".to_string());

        let mut deleted = Vec::new();
        let mut updated = Vec::new();
        let mut inserted = Vec::new();
        for change in PrefixMapDiff::new(&map_a, &map_b) {
            match change {
                MapChange::Delete(key) => deleted.push(*key),
                MapChange::Update(key, value) => updated.push((*key, value.clone())),
                MapChange::Insert(key, value) => inserted.push((*key, value.clone())),
            }
        }

        assert_eq!(vec!["192.168.0.0/24".parse::<Ipv4Net>().unwrap()], deleted);
        assert_eq!(
            vec![(
                "192.168.0.0/26".parse::<Ipv4Net>().unwrap(),
                "to update".to_string()
            ),],
            updated
        );
        assert_eq!(
            vec![(
                "192.168.0.0/27".parse::<Ipv4Net>().unwrap(),
                "to insert".to_string()
            )],
            inserted
        );
    }
}
