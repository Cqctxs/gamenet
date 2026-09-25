use crate::identity::TunnelToken;
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
        /// Stable 32-byte identity token that determines which public port this agent gets.
        token: TunnelToken,
        /// Hash of the separate recovery key; the key itself is never sent during hosting.
        recovery_id: [u8; 32],
    },
    /// Server -> Agent: "Your tunnel is live, players connect here"
    TunnelReady { public_port: u16 },
    /// Server -> Agent: "A new player connected" (sent over control stream)
    NewConnection { stream_id: u64 },
    /// Either direction: something went wrong
    Error { message: String },
    /// Host -> Relay: transfer a disconnected host's short port claim to a new token.
    RotateIdentity {
        old_token: TunnelToken,
        new_token: TunnelToken,
    },
    /// Relay -> Host: the old port claim is revoked; `None` means it had expired.
    IdentityRotated { public_port: Option<u16> },
    /// Host -> Relay: prove knowledge of recovery key and replace the ordinary identity.
    RecoverIdentity {
        recovery_secret: TunnelToken,
        new_token: TunnelToken,
    },
    /// Relay -> Host: the claim belongs to the replacement identity.
    IdentityRecovered { public_port: u16 },
}

/// Supported transport protocols.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
