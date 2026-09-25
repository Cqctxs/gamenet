use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use gamenet_core::identity::TunnelToken;

pub const PORT_START: u16 = 10000;
pub const PORT_END: u16 = 10999;
pub const MAX_TUNNELS_PER_IP: usize = 5;
pub const GRACE_MS: u64 = 300_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TokenId(pub [u8; 32]);

impl TokenId {
    pub fn from_token(token: &TunnelToken) -> Self {
        let hash = ring::digest::digest(&ring::digest::SHA256, token);
        Self(hash.as_ref().try_into().expect("SHA-256 has 32 bytes"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(u64);

#[derive(Clone, Debug)]
pub struct LeaseRecord {
    pub token_id: TokenId,
    pub port: u16,
    pub last_ip: Option<IpAddr>,
    pub expires_at_ms: u64,
}

#[derive(Clone)]
enum LeaseStatus {
    Active { session_id: SessionId },
    Grace { expires_at_ms: u64 },
}

#[derive(Clone)]
struct Lease {
    port: u16,
    last_ip: Option<IpAddr>,
    status: LeaseStatus,
}

#[derive(Clone, Default)]
pub struct LeaseTable {
    leases: HashMap<TokenId, Lease>,
    next_session_id: u64,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn candidate_ports(
        &mut self,
        token_id: TokenId,
        peer_ip: IpAddr,
        now_ms: u64,
    ) -> anyhow::Result<Vec<u16>> {
        self.reap_expired(now_ms);
        if let Some(lease) = self.leases.get(&token_id) {
            anyhow::ensure!(
                matches!(lease.status, LeaseStatus::Grace { .. }),
                "This identity already has an active tunnel"
            );
            self.check_ip_quota(peer_ip, lease.last_ip == Some(peer_ip))?;
            return Ok(vec![lease.port]);
        }
        self.check_ip_quota(peer_ip, false)?;
        let occupied: HashSet<u16> = self.leases.values().map(|lease| lease.port).collect();
        let ports: Vec<u16> = (PORT_START..=PORT_END)
            .filter(|port| !occupied.contains(port))
            .collect();
        anyhow::ensure!(!ports.is_empty(), "Port pool exhausted");
        Ok(ports)
    }

    pub fn activate(
        &mut self,
        token_id: TokenId,
        peer_ip: IpAddr,
        port: u16,
        now_ms: u64,
    ) -> anyhow::Result<SessionId> {
        anyhow::ensure!(
            self.candidate_ports(token_id, peer_ip, now_ms)?
                .contains(&port),
            "Port is not available to this identity"
        );
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Session ID exhausted"))?;
        let session_id = SessionId(self.next_session_id);
        self.leases.insert(
            token_id,
            Lease {
                port,
                last_ip: Some(peer_ip),
                status: LeaseStatus::Active { session_id },
            },
        );
        Ok(session_id)
    }

    pub fn end(&mut self, token_id: TokenId, session_id: SessionId, now_ms: u64) -> bool {
        let Some(lease) = self.leases.get_mut(&token_id) else {
            return false;
        };
        if !matches!(lease.status, LeaseStatus::Active { session_id: current } if current == session_id)
        {
            return false;
        }
        lease.status = LeaseStatus::Grace {
            expires_at_ms: now_ms.saturating_add(GRACE_MS),
        };
        true
    }

    pub fn reap_expired(&mut self, now_ms: u64) {
        self.leases.retain(|_, lease| {
            !matches!(lease.status, LeaseStatus::Grace { expires_at_ms } if expires_at_ms <= now_ms)
        });
    }

    pub fn snapshot(&self, now_ms: u64) -> Vec<LeaseRecord> {
        self.leases
            .iter()
            .map(|(&token_id, lease)| LeaseRecord {
                token_id,
                port: lease.port,
                last_ip: lease.last_ip,
                expires_at_ms: match lease.status {
                    LeaseStatus::Active { .. } => now_ms.saturating_add(GRACE_MS),
                    LeaseStatus::Grace { expires_at_ms } => expires_at_ms,
                },
            })
            .collect()
    }

    pub fn restore(records: Vec<LeaseRecord>, now_ms: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            records.len() <= usize::from(PORT_END - PORT_START + 1),
            "Too many leases"
        );
        let mut table = Self::new();
        let mut ports = HashSet::new();
        let mut tokens = HashSet::new();
        for record in records {
            anyhow::ensure!(
                (PORT_START..=PORT_END).contains(&record.port),
                "Invalid lease port"
            );
            anyhow::ensure!(ports.insert(record.port), "Duplicate lease port");
            anyhow::ensure!(tokens.insert(record.token_id), "Duplicate token ID");
            if record.expires_at_ms <= now_ms {
                continue;
            }
            table.leases.insert(
                record.token_id,
                Lease {
                    port: record.port,
                    last_ip: record.last_ip,
                    status: LeaseStatus::Grace {
                        expires_at_ms: record.expires_at_ms,
                    },
                },
            );
        }
        Ok(table)
    }

    #[cfg(test)]
    pub fn active_session(&self, token_id: TokenId) -> Option<SessionId> {
        match self.leases.get(&token_id)?.status {
            LeaseStatus::Active { session_id } => Some(session_id),
            LeaseStatus::Grace { .. } => None,
        }
    }

    #[cfg(test)]
    pub fn grace_port(&self, token_id: TokenId) -> Option<u16> {
        let lease = self.leases.get(&token_id)?;
        matches!(lease.status, LeaseStatus::Grace { .. }).then_some(lease.port)
    }

    fn check_ip_quota(&self, peer_ip: IpAddr, already_counted: bool) -> anyhow::Result<()> {
        let count = self
            .leases
            .values()
            .filter(|lease| lease.last_ip == Some(peer_ip))
            .count();
        anyhow::ensure!(
            already_counted || count < MAX_TUNNELS_PER_IP,
            "Too many tunnels from {} (max {})",
            peer_ip,
            MAX_TUNNELS_PER_IP
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(address: &str) -> std::net::IpAddr {
        address.parse().unwrap()
    }

    #[test]
    fn reconnect_keeps_port_for_five_minutes_then_releases_it() {
        let token = TokenId::from_token(&[7; 32]);
        let mut table = LeaseTable::new();
        let host = ip("192.0.2.1");
        let port = table.candidate_ports(token, host, 1_000).unwrap()[0];
        let session = table.activate(token, host, port, 1_000).unwrap();

        assert!(table.end(token, session, 1_000));
        assert_eq!(
            table.candidate_ports(token, host, 300_999).unwrap(),
            vec![port]
        );
        table.reap_expired(301_000);
        assert_eq!(table.grace_port(token), None);
        assert_eq!(
            table
                .candidate_ports(TokenId::from_token(&[8; 32]), host, 301_000)
                .unwrap()[0],
            port
        );
    }

    #[test]
    fn duplicate_active_token_and_stale_cleanup_do_not_replace_current_session() {
        let token = TokenId::from_token(&[9; 32]);
        let host = ip("192.0.2.1");
        let mut table = LeaseTable::new();
        let port = table.candidate_ports(token, host, 0).unwrap()[0];
        let old = table.activate(token, host, port, 0).unwrap();
        assert!(table.candidate_ports(token, host, 1).is_err());
        assert!(table.end(token, old, 1));
        let new = table.activate(token, host, port, 2).unwrap();
        assert!(!table.end(token, old, 3));
        assert_eq!(table.active_session(token), Some(new));
    }

    #[test]
    fn grace_counts_against_ip_limit_and_reconnect_transfers_quota() {
        let mut table = LeaseTable::new();
        let old_ip = ip("192.0.2.1");
        let new_ip = ip("192.0.2.2");
        for n in 0..5 {
            let token = TokenId::from_token(&[n; 32]);
            let port = table.candidate_ports(token, old_ip, 0).unwrap()[0];
            let session = table.activate(token, old_ip, port, 0).unwrap();
            assert!(table.end(token, session, 1));
        }
        assert!(
            table
                .candidate_ports(TokenId::from_token(&[99; 32]), old_ip, 2)
                .is_err()
        );
        let token = TokenId::from_token(&[0; 32]);
        let port = table.candidate_ports(token, new_ip, 2).unwrap()[0];
        table.activate(token, new_ip, port, 2).unwrap();
        assert!(
            table
                .candidate_ports(TokenId::from_token(&[99; 32]), old_ip, 3)
                .is_ok()
        );
    }

    #[test]
    fn saved_active_lease_recovers_as_grace() {
        let token = TokenId::from_token(&[4; 32]);
        let host = ip("192.0.2.4");
        let mut table = LeaseTable::new();
        let port = table.candidate_ports(token, host, 1_000).unwrap()[0];
        table.activate(token, host, port, 1_000).unwrap();
        let restored = LeaseTable::restore(table.snapshot(1_000), 2_000).unwrap();
        assert_eq!(restored.grace_port(token), Some(port));
    }
}
