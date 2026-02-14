use crate::protocol::Protocol;

/// A game preset with sensible defaults so users can type
/// `gamenet host minecraft` instead of remembering port numbers.
pub struct GamePreset {
    pub name: &'static str,
    pub protocol: Protocol,
    pub default_port: u16,
}

pub const PRESETS: &[GamePreset] = &[
    GamePreset { name: "minecraft", protocol: Protocol::Tcp, default_port: 25565 },
    GamePreset { name: "bedrock",   protocol: Protocol::Udp, default_port: 19132 },
    GamePreset { name: "valheim",   protocol: Protocol::Udp, default_port: 2456  },
    GamePreset { name: "terraria",  protocol: Protocol::Tcp, default_port: 7777  },
    GamePreset { name: "factorio",  protocol: Protocol::Udp, default_port: 34197 },
];

/// Look up a game preset by name (case-insensitive).
pub fn find_preset(name: &str) -> Option<&'static GamePreset> {
    PRESETS.iter().find(|p| p.name.eq_ignore_ascii_case(name))
}
