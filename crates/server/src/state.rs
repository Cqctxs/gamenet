use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use gamenet_core::identity::TunnelToken;
use tokio::net::TcpListener;

use crate::lease::{LeaseTable, SessionId, TokenId};
use crate::lease_store::LeaseStore;

pub struct ServerState {
    pub(crate) leases: LeaseTable,
    store: LeaseStore,
    persistence_healthy: bool,
}

pub struct Registration {
    pub listener: TcpListener,
    pub public_port: u16,
    pub token_id: TokenId,
    pub session_id: SessionId,
}

#[cfg(test)]
pub(crate) static PORT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

impl ServerState {
    pub fn load_or_new(path: &Path, now_ms: u64) -> anyhow::Result<Self> {
        let (store, leases) = LeaseStore::load_or_create(path, now_ms)?;
        Ok(Self {
            leases,
            store,
            persistence_healthy: true,
        })
    }

    pub async fn register(
        &mut self,
        token: TunnelToken,
        peer_ip: IpAddr,
        now_ms: u64,
    ) -> anyhow::Result<Registration> {
        anyhow::ensure!(self.persistence_healthy, "Lease storage is unavailable");
        let token_id = TokenId::from_token(&token);
        let candidates = self.leases.candidate_ports(token_id, peer_ip, now_ms)?;
        for port in candidates {
            let listener = match TcpListener::bind(("0.0.0.0", port)).await {
                Ok(listener) => listener,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error.into()),
            };
            let mut staged = self.leases.clone();
            let session_id = staged.activate(token_id, peer_ip, port, now_ms)?;
            if let Err(error) = self.store.save(&staged.snapshot(now_ms)) {
                self.persistence_healthy = false;
                return Err(error);
            }
            self.leases = staged;
            return Ok(Registration {
                listener,
                public_port: port,
                token_id,
                session_id,
            });
        }
        anyhow::bail!("No free TCP port can be bound in the relay's port range")
    }

    pub fn end(
        &mut self,
        token_id: TokenId,
        session_id: SessionId,
        now_ms: u64,
    ) -> anyhow::Result<bool> {
        if !self.leases.end(token_id, session_id, now_ms) {
            return Ok(false);
        }
        if let Err(error) = self.store.save(&self.leases.snapshot(now_ms)) {
            self.persistence_healthy = false;
            return Err(error);
        }
        Ok(true)
    }

    pub fn refresh_and_save(&mut self, now_ms: u64) -> anyhow::Result<()> {
        self.leases.reap_expired(now_ms);
        if let Err(error) = self.store.save(&self.leases.snapshot(now_ms)) {
            self.persistence_healthy = false;
            return Err(error);
        }
        self.persistence_healthy = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(address: &str) -> IpAddr {
        address.parse().unwrap()
    }

    #[tokio::test]
    async fn chooses_a_port_that_is_actually_bound_before_registration_returns() {
        let _port_guard = PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let occupied = TcpListener::bind(("0.0.0.0", 10000)).await.ok();
        let mut state = ServerState::load_or_new(&path, 1_000).unwrap();
        let registered = state
            .register([1; 32], ip("192.0.2.1"), 1_000)
            .await
            .unwrap();
        assert_ne!(registered.public_port, 10000);
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", registered.public_port))
                .await
                .is_ok()
        );
        drop(occupied);
    }

    #[tokio::test]
    async fn refuses_duplicate_active_identity_without_displacing_listener() {
        let _port_guard = PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = ServerState::load_or_new(&path, 1_000).unwrap();
        let first = state
            .register([2; 32], ip("192.0.2.1"), 1_000)
            .await
            .unwrap();
        assert!(
            state
                .register([2; 32], ip("192.0.2.1"), 1_001)
                .await
                .is_err()
        );
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", first.public_port))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn failed_persistence_never_commits_a_port() {
        let _port_guard = PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("state.json");
        let mut state = ServerState::load_or_new(&path, 1_000).unwrap();
        assert!(
            state
                .register([3; 32], ip("192.0.2.1"), 1_000)
                .await
                .is_err()
        );
        assert_eq!(
            state.leases.active_session(TokenId::from_token(&[3; 32])),
            None
        );
    }

    #[tokio::test]
    async fn grace_port_stays_reserved_and_reconnects_after_listener_closes() {
        let _port_guard = PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = ServerState::load_or_new(&path, 1_000).unwrap();
        let first = state
            .register([4; 32], ip("192.0.2.1"), 1_000)
            .await
            .unwrap();
        let port = first.public_port;
        drop(first.listener);
        state.end(first.token_id, first.session_id, 1_000).unwrap();
        let other = state
            .register([5; 32], ip("192.0.2.1"), 1_001)
            .await
            .unwrap();
        assert_ne!(other.public_port, port);
        let resumed = state
            .register([4; 32], ip("192.0.2.1"), 300_999)
            .await
            .unwrap();
        assert_eq!(resumed.public_port, port);
    }

    #[tokio::test]
    async fn failed_cleanup_blocks_admission_until_state_can_be_saved() {
        let _port_guard = PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("state-dir");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("state.json");
        let mut state = ServerState::load_or_new(&path, 1_000).unwrap();
        let first = state
            .register([10; 32], ip("192.0.2.1"), 1_000)
            .await
            .unwrap();
        drop(first.listener);
        std::fs::remove_dir_all(&parent).unwrap();
        assert!(state.end(first.token_id, first.session_id, 2_000).is_err());
        assert!(
            state
                .register([11; 32], ip("192.0.2.1"), 2_001)
                .await
                .is_err()
        );
        std::fs::create_dir(&parent).unwrap();
        state.refresh_and_save(2_002).unwrap();
        assert!(
            state
                .register([11; 32], ip("192.0.2.1"), 2_003)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn restart_recovers_port_then_recycles_it_after_expiry() {
        let _port_guard = PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut first_state = ServerState::load_or_new(&path, 1_000).unwrap();
        let first = first_state
            .register([12; 32], ip("192.0.2.1"), 1_000)
            .await
            .unwrap();
        let port = first.public_port;
        drop(first);
        drop(first_state);

        let mut restarted = ServerState::load_or_new(&path, 2_000).unwrap();
        let resumed = restarted
            .register([12; 32], ip("192.0.2.1"), 2_000)
            .await
            .unwrap();
        assert_eq!(resumed.public_port, port);
        drop(resumed);
        drop(restarted);

        let mut expired = ServerState::load_or_new(&path, 302_000).unwrap();
        let other = expired
            .register([13; 32], ip("192.0.2.2"), 302_000)
            .await
            .unwrap();
        assert_eq!(other.public_port, port);
    }
}
