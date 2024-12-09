// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//! Model for configuration variables and maps of our eBPF application
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use ipnet::{IpNet, Ipv4Net};
use prefix_trie::{map::Iter as PrefixMapIter, Prefix, PrefixMap};

pub enum MapChange<'a, P, T> {
    Insert {
        key: &'a P,
        value: &'a T,
    },
    Update {
        key: &'a P,
        old: &'a T,
        value: &'a T,
    },
    Delete {
        key: &'a P,
        old: &'a T,
    },
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
                        return Some(MapChange::Update {
                            key,
                            old: value,
                            value: other_value,
                        });
                    }
                } else {
                    return Some(MapChange::Delete { key, old: value });
                }
            }
            self.map_a_finished = true
        }

        for (key, value) in self.map_b_iter.by_ref() {
            if self.map_a.get(key).is_none() {
                return Some(MapChange::Insert { key, value });
            }
        }

        None
    }
}

pub trait IpAddress: Sized {
    type Data;
    const LEN: u8;

    fn is_unspecified(&self) -> bool;

    fn ip_addr(&self) -> IpAddr;

    fn data(&self) -> Self::Data;

    fn from_data(data: Self::Data) -> Self;

    fn from_ip_addr(addr: IpAddr) -> Option<Self>;

    fn unspecified() -> Self;
}

#[allow(dead_code)]
pub trait IpNetwork: Sized {
    type Addr: IpAddress;

    fn prefix_len(&self) -> u8;

    fn addr(&self) -> Self::Addr;

    fn from(addr: Self::Addr, prefix_len: u8) -> Self;

    fn from_ipnet(net: IpNet) -> Option<Self>;

    fn from_addr(addr: Self::Addr) -> Self {
        Self::from(addr, Self::Addr::LEN)
    }
}

impl IpAddress for Ipv4Addr {
    type Data = [u8; 4];
    const LEN: u8 = 32;

    fn is_unspecified(&self) -> bool {
        self.is_unspecified()
    }

    fn ip_addr(&self) -> IpAddr {
        IpAddr::V4(*self)
    }

    fn data(&self) -> Self::Data {
        self.octets()
    }

    fn from_data(data: Self::Data) -> Self {
        From::from(data)
    }

    fn from_ip_addr(addr: IpAddr) -> Option<Self> {
        if let IpAddr::V4(v4) = addr {
            Some(v4)
        } else {
            None
        }
    }

    fn unspecified() -> Self {
        Self::UNSPECIFIED
    }
}

#[cfg(feature = "ipv6")]
impl IpAddress for Ipv6Addr {
    type Data = [u8; 16];
    const LEN: u8 = 128;

    fn is_unspecified(&self) -> bool {
        self.is_unspecified()
    }

    fn ip_addr(&self) -> IpAddr {
        IpAddr::V6(*self)
    }

    fn data(&self) -> Self::Data {
        self.octets()
    }

    fn from_data(data: Self::Data) -> Self {
        From::from(data)
    }

    fn from_ip_addr(addr: IpAddr) -> Option<Self> {
        if let IpAddr::V6(v6) = addr {
            Some(v6)
        } else {
            None
        }
    }

    fn unspecified() -> Self {
        Self::UNSPECIFIED
    }
}

impl IpNetwork for Ipv4Net {
    type Addr = Ipv4Addr;

    fn prefix_len(&self) -> u8 {
        Ipv4Net::prefix_len(self)
    }

    fn addr(&self) -> Self::Addr {
        Ipv4Net::addr(self)
    }

    fn from(addr: Self::Addr, prefix_len: u8) -> Self {
        Ipv4Net::new_assert(addr, prefix_len)
    }

    fn from_ipnet(net: IpNet) -> Option<Self> {
        if let IpNet::V4(v4) = net {
            Some(v4)
        } else {
            None
        }
    }
}

#[cfg(feature = "ipv6")]
impl IpNetwork for Ipv6Net {
    type Addr = Ipv6Addr;

    fn prefix_len(&self) -> u8 {
        Ipv6Net::prefix_len(self)
    }

    fn addr(&self) -> Self::Addr {
        Ipv6Net::addr(self)
    }

    fn from(addr: Self::Addr, prefix_len: u8) -> Self {
        Ipv6Net::new_assert(addr, prefix_len)
    }

    fn from_ipnet(net: IpNet) -> Option<Self> {
        if let IpNet::V6(v6) = net {
            Some(v6)
        } else {
            None
        }
    }
}

impl<T> IpAddress for T
where
    T: IpNetwork,
    T::Addr: IpAddress,
{
    type Data = <T::Addr as IpAddress>::Data;
    const LEN: u8 = <T::Addr as IpAddress>::LEN;

    fn is_unspecified(&self) -> bool {
        self.prefix_len() == Self::LEN && self.addr().is_unspecified()
    }

    fn ip_addr(&self) -> IpAddr {
        self.addr().ip_addr()
    }

    fn data(&self) -> Self::Data {
        self.addr().data()
    }

    fn from_data(data: Self::Data) -> Self {
        Self::from_addr(T::Addr::from_data(data))
    }

    fn from_ip_addr(addr: IpAddr) -> Option<Self> {
        let addr = T::Addr::from_ip_addr(addr)?;
        Some(Self::from_addr(addr))
    }

    fn unspecified() -> Self {
        Self::from_addr(T::Addr::unspecified())
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
                MapChange::Delete { key, .. } => deleted.push(*key),
                MapChange::Update { key, value, .. } => updated.push((*key, value.clone())),
                MapChange::Insert { key, value } => inserted.push((*key, value.clone())),
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
