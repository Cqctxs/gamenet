use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HostSource {
    V4(Ipv4Addr),
    V6([u8; 8]),
}

impl From<IpAddr> for HostSource {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip),
            IpAddr::V6(ip) => {
                if let Some(mapped) = ip.to_ipv4_mapped() {
                    return Self::V4(mapped);
                }
                let octets = ip.octets();
                Self::V6(octets[..8].try_into().expect("IPv6 prefix has eight bytes"))
            }
        }
    }
}

pub struct PendingByIp {
    limit: usize,
    counts: Mutex<HashMap<HostSource, usize>>,
}

pub struct PendingHostPermit {
    pending: Arc<PendingByIp>,
    source: HostSource,
}

impl PendingByIp {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PendingHostPermit> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let source = HostSource::from(ip);
        let count = counts.entry(source).or_default();
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(PendingHostPermit {
            pending: Arc::clone(self),
            source,
        })
    }

    #[cfg(test)]
    pub fn active_for(&self, ip: IpAddr) -> usize {
        let counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        counts
            .get(&HostSource::from(ip))
            .copied()
            .unwrap_or_default()
    }
}

impl Drop for PendingHostPermit {
    fn drop(&mut self) {
        let mut counts = self
            .pending
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(count) = counts.get_mut(&self.source) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.source);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn pending_host_slots_are_limited_per_ip_and_released_on_drop() {
        let pending = Arc::new(PendingByIp::new(2));
        let first_ip = "192.0.2.1".parse().unwrap();
        let other_ip = "192.0.2.2".parse().unwrap();
        let first = pending.try_acquire(first_ip).unwrap();
        let second = pending.try_acquire(first_ip).unwrap();
        assert!(pending.try_acquire(first_ip).is_none());
        let other = pending.try_acquire(other_ip).unwrap();

        drop(first);
        assert!(pending.try_acquire(first_ip).is_some());
        drop(second);
        drop(other);
        assert_eq!(pending.active_for(first_ip), 0);
        assert_eq!(pending.active_for(other_ip), 0);
    }

    #[test]
    fn ipv6_addresses_in_one_network_share_pending_slots() {
        let pending = Arc::new(PendingByIp::new(2));
        let first = "2001:db8:1:2::1".parse().unwrap();
        let second = "2001:db8:1:2::2".parse().unwrap();
        let third = "2001:db8:1:2::3".parse().unwrap();
        let other = "2001:db8:1:3::1".parse().unwrap();
        let _first = pending.try_acquire(first).unwrap();
        let _second = pending.try_acquire(second).unwrap();
        assert!(pending.try_acquire(third).is_none());
        assert!(pending.try_acquire(other).is_some());
    }

    #[test]
    fn ipv4_mapped_ipv6_address_shares_ipv4_quota() {
        let ipv4: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(HostSource::from(ipv4), HostSource::from(mapped));
    }
}
