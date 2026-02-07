use serde::{Deserialize, Serialize};

/// Control messages sent over the control stream
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlMessage {
    /// Register a new tunnel
    Register {
        protocol: Protocol,
        local_port: u16,
    },
    /// Tunnel is ready
    TunnelReady {
        public_port: u16,
    },
    /// A new player connection is incoming
    NewConnection {
        stream_id: u64,
        data_port: u16,
    },
    Error {
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
