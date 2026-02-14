use std::collections::HashMap;

/// One entry in our tunnel registry.
pub struct TunnelEntry {
    pub public_port: u16,
    pub local_port: u16,
}

/// Shared state that tracks all active tunnels.
///
/// Each agent connection gets a unique public port from this registry.
/// When the agent disconnects, the entry is removed so the port can be reused.
pub struct ServerState {
    tunnels: HashMap<u16, TunnelEntry>,
    next_port: u16,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
            next_port: 10000,
        }
    }

    /// Assign the next available public port for a new tunnel.
    pub fn assign_port(&mut self, local_port: u16) -> u16 {
        let port = self.next_port;
        self.tunnels.insert(
            port,
            TunnelEntry {
                public_port: port,
                local_port,
            },
        );
        self.next_port += 1;
        port
    }

    /// Remove a tunnel entry when an agent disconnects.
    pub fn remove(&mut self, public_port: u16) {
        self.tunnels.remove(&public_port);
    }

    /// Number of active tunnels.
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }
}
