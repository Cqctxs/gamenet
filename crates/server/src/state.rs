use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use gamenet_core::identity::TunnelToken;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub const MAX_TUNNELS_PER_IP: usize = 5;
const PORT_RANGE_START: u16 = 10000;
const PORT_RANGE_END: u16 = 10999;

pub struct TunnelEntry {
    pub public_port: u16,
    pub local_port: u16,
    pub peer_ip: IpAddr,
}

pub struct ServerState {
    // Permanent: token → reserved port (written to disk on every change)
    token_ports: HashMap<TunnelToken, u16>,
    // Transient: populated only while an agent is connected
    active_tunnels: HashMap<u16, TunnelEntry>,
    // Ports not yet assigned to any token
    free_ports: VecDeque<u16>,
    connections_per_ip: HashMap<IpAddr, usize>,
    state_path: PathBuf,
}

// ── Persistence ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct PersistedState {
    token_ports: Vec<(String, u16)>,
}

fn token_to_hex(token: &TunnelToken) -> String {
    token.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_token(s: &str) -> anyhow::Result<TunnelToken> {
    anyhow::ensure!(s.len() == 64, "Token hex must be 64 chars, got {}", s.len());
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{}", e)))
        .collect::<anyhow::Result<_>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Wrong token byte count"))
}

// ── Construction ─────────────────────────────────────────────────────────────

impl ServerState {
    pub fn new() -> Self {
        Self::new_with_path("./gamenet-state.json")
    }

    pub fn new_with_path(path: impl Into<PathBuf>) -> Self {
        let free_ports = (PORT_RANGE_START..=PORT_RANGE_END).collect();
        Self {
            token_ports: HashMap::new(),
            active_tunnels: HashMap::new(),
            free_ports,
            connections_per_ip: HashMap::new(),
            state_path: path.into(),
        }
    }

    /// Load from disk if the file exists; otherwise start fresh.
    pub fn load_or_new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        match Self::load(&path) {
            Ok(s) => s,
            Err(e) => {
                if path.exists() {
                    warn!("Failed to load state from {:?}: {} — starting fresh", path, e);
                }
                Self::new_with_path(path)
            }
        }
    }

    fn load(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let persisted: PersistedState = serde_json::from_str(&json)?;
        let mut state = Self::new_with_path(path);
        for (hex, port) in persisted.token_ports {
            let token = hex_to_token(&hex)?;
            state.token_ports.insert(token, port);
            state.free_ports.retain(|&p| p != port);
        }
        Ok(state)
    }

    fn save(&self) {
        let persisted = PersistedState {
            token_ports: self
                .token_ports
                .iter()
                .map(|(k, &v)| (token_to_hex(k), v))
                .collect(),
        };
        match serde_json::to_string_pretty(&persisted) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.state_path, json) {
                    warn!("Failed to persist state to {:?}: {}", self.state_path, e);
                }
            }
            Err(e) => warn!("Failed to serialize state: {}", e),
        }
    }
}

// ── Mutations ─────────────────────────────────────────────────────────────────

impl ServerState {
    /// Assign or resume a port for the given token.
    ///
    /// Returns Err if the IP has too many active tunnels or the port pool is exhausted.
    pub fn assign_or_resume(
        &mut self,
        token: TunnelToken,
        local_port: u16,
        peer_ip: IpAddr,
    ) -> anyhow::Result<u16> {
        let count = self.connections_per_ip.get(&peer_ip).copied().unwrap_or(0);
        anyhow::ensure!(
            count < MAX_TUNNELS_PER_IP,
            "Too many tunnels from {} (max {})",
            peer_ip,
            MAX_TUNNELS_PER_IP
        );

        let port = if let Some(&existing) = self.token_ports.get(&token) {
            existing
        } else {
            let p = self
                .free_ports
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("Port pool exhausted (max 1 000 tunnels)"))?;
            self.token_ports.insert(token, p);
            self.save(); // Persist new token→port mapping immediately
            p
        };

        self.active_tunnels.insert(
            port,
            TunnelEntry { public_port: port, local_port, peer_ip },
        );
        *self.connections_per_ip.entry(peer_ip).or_insert(0) += 1;
        Ok(port)
    }

    /// Mark a tunnel as disconnected. Port stays reserved for the token permanently.
    pub fn release(&mut self, public_port: u16) {
        if let Some(entry) = self.active_tunnels.remove(&public_port) {
            let count = self.connections_per_ip.entry(entry.peer_ip).or_insert(0);
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.connections_per_ip.remove(&entry.peer_ip);
            }
        }
        // token_ports intentionally NOT cleared — port stays reserved for that token
    }

    pub fn tunnel_count(&self) -> usize {
        self.active_tunnels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(suffix: &str) -> PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!("gamenet-state-{}-{}.json", suffix, ns))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn new_token_gets_a_port_in_range() {
        let mut state = ServerState::new_with_path(temp_path("range"));
        let port = state.assign_or_resume([1u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert!((PORT_RANGE_START..=PORT_RANGE_END).contains(&port));
    }

    #[test]
    fn same_token_gets_same_port_after_disconnect() {
        let mut state = ServerState::new_with_path(temp_path("same"));
        let port1 = state.assign_or_resume([2u8; 32], 25565, ip("1.2.3.4")).unwrap();
        state.release(port1);
        let port2 = state.assign_or_resume([2u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert_eq!(port1, port2);
    }

    #[test]
    fn different_tokens_get_different_ports() {
        let mut state = ServerState::new_with_path(temp_path("diff"));
        let p1 = state.assign_or_resume([3u8; 32], 25565, ip("1.2.3.4")).unwrap();
        let p2 = state.assign_or_resume([4u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn ip_limit_is_enforced() {
        let mut state = ServerState::new_with_path(temp_path("iplimit"));
        let attacker = ip("1.2.3.4");
        for i in 0..MAX_TUNNELS_PER_IP {
            let mut token = [0u8; 32];
            token[0] = i as u8;
            state.assign_or_resume(token, 25565, attacker).unwrap();
        }
        let mut extra_token = [0u8; 32];
        extra_token[0] = 99;
        assert!(state.assign_or_resume(extra_token, 25565, attacker).is_err());
    }

    #[test]
    fn release_frees_ip_slot() {
        let mut state = ServerState::new_with_path(temp_path("release"));
        let my_ip = ip("5.5.5.5");
        let mut ports = vec![];
        for i in 0..MAX_TUNNELS_PER_IP {
            let mut token = [0u8; 32];
            token[0] = i as u8;
            ports.push(state.assign_or_resume(token, 25565, my_ip).unwrap());
        }
        state.release(ports[0]);
        let mut new_token = [0u8; 32];
        new_token[0] = 100;
        assert!(state.assign_or_resume(new_token, 25565, my_ip).is_ok());
    }

    #[test]
    fn save_and_load_preserves_token_port_mapping() {
        let path = temp_path("persist");
        let token = [42u8; 32];
        let port = {
            let mut state = ServerState::new_with_path(&path);
            state.assign_or_resume(token, 25565, ip("1.2.3.4")).unwrap()
        };
        let mut loaded = ServerState::load_or_new(&path);
        let port2 = loaded.assign_or_resume(token, 25565, ip("2.3.4.5")).unwrap();
        assert_eq!(port, port2);
        std::fs::remove_file(&path).ok();
    }
}
