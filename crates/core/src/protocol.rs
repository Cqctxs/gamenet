use serde::{Deserialize, Serialize};

/// Control messages sent over the control stream.
///
/// Serialized with bincode and framed with a 4-byte length prefix
/// (see [`crate::message`] for the send/recv helpers).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlMessage {
    /// Agent -> Server: "I want to host a game"
    Register {
        protocol: Protocol,
        local_port: u16,
    },
    /// Server -> Agent: "Your tunnel is live, players connect here"
    TunnelReady {
        public_port: u16,
    },
    /// Server -> Agent: "A player just joined, open a data connection on this port"
    NewConnection {
        stream_id: u64,
        data_port: u16,
    },
    /// Either direction: something went wrong
    Error {
        message: String,
    },
}

/// Supported transport protocols.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
