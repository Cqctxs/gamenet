use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use gamenet_core::identity::TunnelToken;

use crate::host_admission::HostSource;

pub const PORT_START: u16 = 10000;
pub const PORT_END: u16 = 10999;
pub const MAX_TUNNELS_PER_IP: usize = 2;
pub const GRACE_MS: u64 = 300_000;
const MAX_RETIRED_IDENTITIES: usize = 8;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationResult {
    Transferred(u16),
    Unchanged(Option<u16>),
}

impl RotationResult {
    pub fn port(self) -> Option<u16> {
        match self {
            Self::Transferred(port) => Some(port),
            Self::Unchanged(port) => port,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LeaseRecord {
    pub token_id: TokenId,
    pub retired_token_ids: Vec<TokenId>,
    pub recovery_id: Option<TokenId>,
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
    retired_token_ids: Vec<TokenId>,
    recovery_id: Option<TokenId>,
    status: LeaseStatus,
}

#[derive(Clone, Default)]
pub struct LeaseTable {
    leases: HashMap<TokenId, Lease>,
    next_session_id: u64,
}

pub struct RecoveryResult {
    pub port: u16,
    pub displaced: Option<(TokenId, SessionId)>,
    pub changed: bool,
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
        anyhow::ensure!(
            !self
                .leases
                .values()
                .any(|lease| lease.retired_token_ids.contains(&token_id)),
            "This identity's port claim has been rotated"
        );
        if let Some(lease) = self.leases.get(&token_id) {
            anyhow::ensure!(
                matches!(lease.status, LeaseStatus::Grace { .. }),
                "This identity already has an active tunnel"
            );
            self.check_ip_quota(
                peer_ip,
                lease.last_ip.map(HostSource::from) == Some(HostSource::from(peer_ip)),
            )?;
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

    #[cfg(test)]
    pub fn activate(
        &mut self,
        token_id: TokenId,
        peer_ip: IpAddr,
        port: u16,
        now_ms: u64,
    ) -> anyhow::Result<SessionId> {
        self.activate_with_recovery(token_id, None, peer_ip, port, now_ms)
    }

    pub fn activate_with_recovery(
        &mut self,
        token_id: TokenId,
        recovery_id: Option<TokenId>,
        peer_ip: IpAddr,
        port: u16,
        now_ms: u64,
    ) -> anyhow::Result<SessionId> {
        anyhow::ensure!(
            self.candidate_ports(token_id, peer_ip, now_ms)?
                .contains(&port),
            "Port is not available to this identity"
        );
        if let Some(recovery_id) = recovery_id {
            anyhow::ensure!(
                !self
                    .leases
                    .iter()
                    .any(|(&id, lease)| id != token_id && lease.recovery_id == Some(recovery_id)),
                "Recovery key already owns another port claim"
            );
        }
        let existing = self.leases.get(&token_id);
        if let (Some(enrolled), Some(presented)) =
            (existing.and_then(|lease| lease.recovery_id), recovery_id)
        {
            anyhow::ensure!(
                enrolled == presented,
                "Recovery key does not match this port claim"
            );
        }
        let recovery_id = existing.and_then(|lease| lease.recovery_id).or(recovery_id);
        let retired_token_ids = existing
            .map(|lease| lease.retired_token_ids.clone())
            .unwrap_or_default();
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
                retired_token_ids,
                recovery_id,
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

    pub fn rotate_claim(
        &mut self,
        old: TokenId,
        new: TokenId,
        now_ms: u64,
    ) -> anyhow::Result<RotationResult> {
        self.reap_expired(now_ms);
        anyhow::ensure!(old != new, "New identity must differ from old identity");
        if let Some(lease) = self.leases.get(&new) {
            if lease.retired_token_ids.contains(&old) {
                return Ok(RotationResult::Unchanged(Some(lease.port)));
            }
            anyhow::bail!("New identity already owns a port claim");
        }
        anyhow::ensure!(
            !self
                .leases
                .values()
                .any(|lease| lease.retired_token_ids.contains(&new)),
            "New identity was previously rotated"
        );
        anyhow::ensure!(
            !self
                .leases
                .values()
                .any(|lease| lease.retired_token_ids.contains(&old)),
            "Old identity's port claim was already rotated to another token"
        );
        let Some(lease) = self.leases.get(&old) else {
            return Ok(RotationResult::Unchanged(None));
        };
        anyhow::ensure!(
            matches!(lease.status, LeaseStatus::Grace { .. }),
            "Stop the active host tunnel before rotating its identity"
        );
        anyhow::ensure!(
            lease.retired_token_ids.is_empty(),
            "This port claim has already been rotated once"
        );
        let mut lease = self.leases.remove(&old).expect("checked above");
        let port = lease.port;
        lease.retired_token_ids.push(old);
        self.leases.insert(new, lease);
        Ok(RotationResult::Transferred(port))
    }

    pub fn recover_claim(
        &mut self,
        recovery_id: TokenId,
        new: TokenId,
        peer_ip: IpAddr,
        now_ms: u64,
    ) -> anyhow::Result<RecoveryResult> {
        self.reap_expired(now_ms);
        let (&old, lease) = self
            .leases
            .iter()
            .find(|(_, lease)| lease.recovery_id == Some(recovery_id))
            .ok_or_else(|| anyhow::anyhow!("No live port claim matches this recovery key"))?;
        if old == new {
            return Ok(RecoveryResult {
                port: lease.port,
                displaced: None,
                changed: false,
            });
        }
        anyhow::ensure!(
            !self.leases.contains_key(&new),
            "New identity already owns a port claim"
        );
        anyhow::ensure!(
            !self
                .leases
                .values()
                .any(|lease| lease.retired_token_ids.contains(&new)),
            "New identity was previously retired"
        );
        self.check_ip_quota(
            peer_ip,
            lease.last_ip.map(HostSource::from) == Some(HostSource::from(peer_ip)),
        )?;
        let mut lease = self.leases.remove(&old).expect("checked above");
        let displaced = match lease.status {
            LeaseStatus::Active { session_id } => Some((old, session_id)),
            LeaseStatus::Grace { .. } => None,
        };
        lease.status = LeaseStatus::Grace {
            expires_at_ms: now_ms.saturating_add(GRACE_MS),
        };
        lease.last_ip = Some(peer_ip);
        lease.retired_token_ids.push(old);
        if lease.retired_token_ids.len() > MAX_RETIRED_IDENTITIES {
            lease.retired_token_ids.remove(0);
        }
        let port = lease.port;
        self.leases.insert(new, lease);
        Ok(RecoveryResult {
            port,
            displaced,
            changed: true,
        })
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
                retired_token_ids: lease.retired_token_ids.clone(),
                recovery_id: lease.recovery_id,
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
        let mut retired = HashSet::new();
        let mut recovery_ids = HashSet::new();
        for record in records {
            anyhow::ensure!(
                (PORT_START..=PORT_END).contains(&record.port),
                "Invalid lease port"
            );
            anyhow::ensure!(ports.insert(record.port), "Duplicate lease port");
            anyhow::ensure!(tokens.insert(record.token_id), "Duplicate token ID");
            if let Some(recovery_id) = record.recovery_id {
                anyhow::ensure!(
                    recovery_ids.insert(recovery_id),
                    "Duplicate recovery key fingerprint"
                );
            }
            anyhow::ensure!(
                record.retired_token_ids.len() <= MAX_RETIRED_IDENTITIES,
                "Too many retired identities"
            );
            for old in &record.retired_token_ids {
                anyhow::ensure!(*old != record.token_id, "Identity cannot retire itself");
                anyhow::ensure!(retired.insert(*old), "Duplicate retired token ID");
            }
            if record.expires_at_ms <= now_ms {
                continue;
            }
            table.leases.insert(
                record.token_id,
                Lease {
                    port: record.port,
                    last_ip: record.last_ip,
                    retired_token_ids: record.retired_token_ids,
                    recovery_id: record.recovery_id,
                    status: LeaseStatus::Grace {
                        expires_at_ms: record.expires_at_ms,
                    },
                },
            );
        }
        anyhow::ensure!(
            tokens.is_disjoint(&retired),
            "Active and retired token overlap"
        );
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
        let source = HostSource::from(peer_ip);
        let count = self
            .leases
            .values()
            .filter(|lease| lease.last_ip.map(HostSource::from) == Some(source))
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
    fn recovery_replaces_active_identity_and_preserves_port() {
        let old = TokenId::from_token(&[1; 32]);
        let new = TokenId::from_token(&[2; 32]);
        let recovery = TokenId::from_token(&[3; 32]);
        let mut table = LeaseTable::new();
        let peer = ip("192.0.2.1");
        let port = table.candidate_ports(old, peer, 1_000).unwrap()[0];
        let session = table
            .activate_with_recovery(old, Some(recovery), peer, port, 1_000)
            .unwrap();

        let result = table.recover_claim(recovery, new, peer, 1_001).unwrap();
        assert_eq!(result.port, port);
        assert_eq!(result.displaced, Some((old, session)));
        assert!(table.candidate_ports(old, peer, 1_002).is_err());
        assert_eq!(table.candidate_ports(new, peer, 1_002).unwrap(), vec![port]);
        assert!(!table.end(old, session, 1_003));
    }

    #[test]
    fn recovery_requires_matching_key_and_survives_rotation_and_restore() {
        let old = TokenId::from_token(&[4; 32]);
        let rotated = TokenId::from_token(&[5; 32]);
        let new = TokenId::from_token(&[6; 32]);
        let recovery = TokenId::from_token(&[7; 32]);
        let mut table = LeaseTable::new();
        let peer = ip("192.0.2.1");
        let port = table.candidate_ports(old, peer, 1_000).unwrap()[0];
        let session = table
            .activate_with_recovery(old, Some(recovery), peer, port, 1_000)
            .unwrap();
        table.end(old, session, 1_001);
        table.rotate_claim(old, rotated, 1_002).unwrap();
        let mut restored = LeaseTable::restore(table.snapshot(1_003), 1_003).unwrap();

        assert!(
            restored
                .recover_claim(TokenId::from_token(&[8; 32]), new, peer, 1_004)
                .is_err()
        );
        assert_eq!(
            restored
                .recover_claim(recovery, new, peer, 1_005)
                .unwrap()
                .port,
            port
        );
        assert!(restored.candidate_ports(old, peer, 1_006).is_err());
        assert!(restored.candidate_ports(rotated, peer, 1_006).is_err());
    }

    #[test]
    fn reconnect_cannot_replace_enrolled_recovery_key() {
        let owner = TokenId::from_token(&[81; 32]);
        let real_key = TokenId::from_token(&[82; 32]);
        let fake_key = TokenId::from_token(&[83; 32]);
        let replacement = TokenId::from_token(&[84; 32]);
        let mut table = LeaseTable::new();
        let peer = ip("192.0.2.1");
        let port = table.candidate_ports(owner, peer, 0).unwrap()[0];
        let session = table
            .activate_with_recovery(owner, Some(real_key), peer, port, 0)
            .unwrap();
        table.end(owner, session, 1);
        assert!(
            table
                .activate_with_recovery(owner, Some(fake_key), peer, port, 2)
                .is_err()
        );
        assert!(table.recover_claim(fake_key, replacement, peer, 3).is_err());
        assert_eq!(
            table
                .recover_claim(real_key, replacement, peer, 3)
                .unwrap()
                .port,
            port
        );
    }

    #[test]
    fn recovery_key_cannot_be_enrolled_for_two_live_claims() {
        let mut table = LeaseTable::new();
        let peer = ip("192.0.2.1");
        let key = TokenId::from_token(&[88; 32]);
        let first = TokenId::from_token(&[89; 32]);
        let second = TokenId::from_token(&[90; 32]);
        let first_port = table.candidate_ports(first, peer, 0).unwrap()[0];
        table
            .activate_with_recovery(first, Some(key), peer, first_port, 0)
            .unwrap();
        let second_port = table.candidate_ports(second, peer, 0).unwrap()[0];
        assert!(
            table
                .activate_with_recovery(second, Some(key), peer, second_port, 0)
                .is_err()
        );
    }

    #[test]
    fn restore_rejects_duplicate_recovery_fingerprints() {
        let key = TokenId::from_token(&[91; 32]);
        let records = vec![
            LeaseRecord {
                token_id: TokenId::from_token(&[92; 32]),
                retired_token_ids: vec![],
                recovery_id: Some(key),
                port: 10000,
                last_ip: None,
                expires_at_ms: 1000,
            },
            LeaseRecord {
                token_id: TokenId::from_token(&[93; 32]),
                retired_token_ids: vec![],
                recovery_id: Some(key),
                port: 10001,
                last_ip: None,
                expires_at_ms: 1000,
            },
        ];
        assert!(LeaseTable::restore(records, 0).is_err());
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
    fn rotation_moves_grace_port_and_blocks_old_token_after_restart() {
        let old = TokenId::from_token(&[31; 32]);
        let new = TokenId::from_token(&[32; 32]);
        let host = ip("192.0.2.31");
        let mut table = LeaseTable::new();
        let port = table.candidate_ports(old, host, 1_000).unwrap()[0];
        let session = table.activate(old, host, port, 1_000).unwrap();

        assert!(table.rotate_claim(old, new, 1_001).is_err());
        assert!(table.end(old, session, 1_001));
        assert_eq!(
            table.rotate_claim(old, new, 1_002).unwrap(),
            RotationResult::Transferred(port)
        );
        assert_eq!(
            table.rotate_claim(old, new, 1_003).unwrap(),
            RotationResult::Unchanged(Some(port))
        );
        assert!(table.candidate_ports(old, host, 1_004).is_err());

        let mut restored = LeaseTable::restore(table.snapshot(1_005), 1_006).unwrap();
        assert!(restored.candidate_ports(old, host, 1_006).is_err());
        assert_eq!(
            restored.candidate_ports(new, host, 1_006).unwrap(),
            vec![port]
        );
        restored.reap_expired(301_001);
        assert!(restored.candidate_ports(old, host, 301_001).is_ok());
    }

    #[test]
    fn competing_rotation_cannot_claim_a_previously_rotated_identity() {
        let old = TokenId::from_token(&[61; 32]);
        let winner = TokenId::from_token(&[62; 32]);
        let loser = TokenId::from_token(&[63; 32]);
        let host = ip("192.0.2.61");
        let mut table = LeaseTable::new();
        let port = table.candidate_ports(old, host, 0).unwrap()[0];
        let session = table.activate(old, host, port, 0).unwrap();
        assert!(table.end(old, session, 1));
        assert_eq!(
            table.rotate_claim(old, winner, 2).unwrap(),
            RotationResult::Transferred(port)
        );

        assert!(table.rotate_claim(old, loser, 3).is_err());
        assert_eq!(table.candidate_ports(winner, host, 3).unwrap(), vec![port]);
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
        for n in 0..2 {
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
    fn two_idle_hosts_from_one_ip_block_a_third_until_a_lease_expires() {
        let mut table = LeaseTable::new();
        let host = ip("192.0.2.1");
        let first = TokenId::from_token(&[1; 32]);
        let second = TokenId::from_token(&[2; 32]);
        let third = TokenId::from_token(&[3; 32]);
        let first_port = table.candidate_ports(first, host, 0).unwrap()[0];
        let first_session = table.activate(first, host, first_port, 0).unwrap();
        let second_port = table.candidate_ports(second, host, 0).unwrap()[0];
        table.activate(second, host, second_port, 0).unwrap();

        assert!(table.candidate_ports(third, host, 0).is_err());
        assert!(table.end(first, first_session, 1));
        assert!(table.candidate_ports(third, host, 1).is_err());
        assert!(table.candidate_ports(first, host, 1).is_ok());
        assert!(table.candidate_ports(third, host, GRACE_MS + 1).is_ok());
    }

    #[test]
    fn ipv6_addresses_in_one_network_share_the_host_quota() {
        let mut table = LeaseTable::new();
        let first_ip = ip("2001:db8:1:2::1");
        let second_ip = ip("2001:db8:1:2::2");
        let rotating_ip = ip("2001:db8:1:2::3");
        let other_network = ip("2001:db8:1:3::1");
        let first = TokenId::from_token(&[11; 32]);
        let second = TokenId::from_token(&[12; 32]);
        let third = TokenId::from_token(&[13; 32]);
        let first_port = table.candidate_ports(first, first_ip, 0).unwrap()[0];
        let first_session = table.activate(first, first_ip, first_port, 0).unwrap();
        let second_port = table.candidate_ports(second, second_ip, 0).unwrap()[0];
        table.activate(second, second_ip, second_port, 0).unwrap();

        assert!(table.candidate_ports(third, rotating_ip, 0).is_err());
        assert!(table.candidate_ports(third, other_network, 0).is_ok());
        assert!(table.end(first, first_session, 0));
        assert_eq!(
            table.candidate_ports(first, rotating_ip, 1).unwrap(),
            vec![first_port]
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
