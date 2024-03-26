// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//! Model for configuration variables and maps of our eBPF application
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

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

#[allow(dead_code)]
pub trait IpNetwork: Sized {
    type Addr;
    const LEN: u8;

    fn prefix_len(&self) -> u8;

    fn addr(&self) -> Self::Addr;

    fn ip_addr(&self) -> IpAddr;

    fn from_addr(addr: Self::Addr) -> Self;

    fn from_ip_addr(addr: IpAddr) -> Option<Self>;
}

impl IpNetwork for Ipv4Net {
    type Addr = Ipv4Addr;
    const LEN: u8 = 32;

    fn prefix_len(&self) -> u8 {
        Ipv4Net::prefix_len(self)
    }

    fn addr(&self) -> Self::Addr {
        Ipv4Net::addr(self)
    }

    fn ip_addr(&self) -> IpAddr {
        IpAddr::V4(self.addr())
    }

    fn from_addr(addr: Self::Addr) -> Self {
        Ipv4Net::new(addr, Self::LEN).unwrap()
    }

    fn from_ip_addr(addr: IpAddr) -> Option<Self> {
        if let IpAddr::V4(v4) = addr {
            Some(Self::from_addr(v4))
        } else {
            None
        }
    }
}

#[cfg(feature = "ipv6")]
impl IpNetwork for Ipv6Net {
    type Addr = Ipv6Addr;
    const LEN: u8 = 128;

    fn prefix_len(&self) -> u8 {
        Ipv6Net::prefix_len(self)
    }

    fn addr(&self) -> Self::Addr {
        Ipv6Net::addr(self)
    }

    fn ip_addr(&self) -> IpAddr {
        IpAddr::V6(self.addr())
    }

    fn from_addr(addr: Self::Addr) -> Self {
        Ipv6Net::new(addr, Self::LEN).unwrap()
    }

    fn from_ip_addr(addr: IpAddr) -> Option<Self> {
        if let IpAddr::V6(v6) = addr {
            Some(Self::from_addr(v6))
        } else {
            None
        }
    }
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
