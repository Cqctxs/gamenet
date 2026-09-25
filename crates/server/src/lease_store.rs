use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::lease::{GRACE_MS, LeaseRecord, LeaseTable, PORT_END, PORT_START, TokenId};

const MAX_STATE_BYTES: u64 = 1024 * 1024;

pub struct LeaseStore {
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedV2 {
    version: u8,
    leases: Vec<PersistedLease>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLease {
    token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired_token_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_id: Option<String>,
    port: u16,
    last_ip: Option<std::net::IpAddr>,
    expires_at_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyState {
    token_ports: Vec<(String, u16)>,
}

impl LeaseStore {
    pub fn load_or_create(path: &Path, now_ms: u64) -> anyhow::Result<(Self, LeaseTable)> {
        let store = Self {
            path: path.to_owned(),
        };
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((store, LeaseTable::new()));
            }
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            metadata.len() <= MAX_STATE_BYTES,
            "Lease state file exceeds 1 MiB"
        );
        let bytes = fs::read(path).with_context(|| format!("Reading {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_STATE_BYTES,
            "Lease state file exceeds 1 MiB"
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if value.get("version").is_some() {
            let persisted: PersistedV2 = serde_json::from_value(value)?;
            anyhow::ensure!(persisted.version == 2, "Unsupported lease state version");
            let records = persisted
                .leases
                .into_iter()
                .map(PersistedLease::into_record)
                .collect::<anyhow::Result<Vec<_>>>()?;
            return Ok((store, LeaseTable::restore(records, now_ms)?));
        }

        let legacy: LegacyState = serde_json::from_value(value)?;
        let table = Self::migrate_legacy(&legacy, now_ms)?;
        store.backup_legacy(&bytes)?;
        store.save(&table.snapshot(now_ms))?;
        Ok((store, table))
    }

    pub fn save(&self, records: &[LeaseRecord]) -> anyhow::Result<()> {
        let mut leases = records
            .iter()
            .map(PersistedLease::from_record)
            .collect::<Vec<_>>();
        leases.sort_by_key(|lease| lease.port);
        let bytes = serde_json::to_vec_pretty(&PersistedV2 { version: 2, leases })?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_STATE_BYTES,
            "Lease state exceeds 1 MiB"
        );
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        set_owner_only(temp.path())?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path).map_err(|error| error.error)?;
        sync_directory(parent)?;
        Ok(())
    }

    fn migrate_legacy(legacy: &LegacyState, now_ms: u64) -> anyhow::Result<LeaseTable> {
        anyhow::ensure!(
            legacy.token_ports.len() <= 1000,
            "Too many legacy reservations"
        );
        let mut tokens = HashSet::new();
        let mut ports = HashSet::new();
        let mut records = Vec::with_capacity(legacy.token_ports.len());
        for (hex, port) in &legacy.token_ports {
            anyhow::ensure!(
                (PORT_START..=PORT_END).contains(port),
                "Invalid legacy port"
            );
            anyhow::ensure!(ports.insert(*port), "Duplicate legacy port");
            let token = parse_hex_32(hex)?;
            anyhow::ensure!(tokens.insert(token), "Duplicate legacy token");
            records.push(LeaseRecord {
                token_id: TokenId::from_token(&token),
                retired_token_ids: Vec::new(),
                recovery_id: None,
                port: *port,
                last_ip: None,
                expires_at_ms: now_ms.saturating_add(GRACE_MS),
            });
        }
        LeaseTable::restore(records, now_ms)
    }

    fn backup_legacy(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let name = self
            .path
            .file_name()
            .context("State path has no file name")?;
        let backup = self
            .path
            .with_file_name(format!("{}.legacy-backup", name.to_string_lossy()));
        let parent = backup.parent().unwrap_or_else(|| Path::new("."));
        match fs::symlink_metadata(&backup) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_file(),
                    "Legacy backup is not a regular file"
                );
                let existing = fs::read(&backup)?;
                anyhow::ensure!(
                    bytes.starts_with(&existing),
                    "Existing legacy backup differs from source state"
                );
                if existing.len() == bytes.len() {
                    #[cfg(unix)]
                    set_owner_only(&backup)?;
                    File::open(&backup)?.sync_all()?;
                    return sync_directory(parent);
                }
                let mut replacement = tempfile::NamedTempFile::new_in(parent)?;
                #[cfg(unix)]
                set_owner_only(replacement.path())?;
                replacement.write_all(bytes)?;
                replacement.as_file().sync_all()?;
                replacement.persist(&backup).map_err(|error| error.error)?;
                return sync_directory(parent);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&backup)
            .with_context(|| format!("Creating {}", backup.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        sync_directory(parent)?;
        Ok(())
    }
}

impl PersistedLease {
    fn from_record(record: &LeaseRecord) -> Self {
        Self {
            token_id: hex_32(&record.token_id.0),
            retired_token_id: None,
            retired_token_ids: record
                .retired_token_ids
                .iter()
                .map(|id| hex_32(&id.0))
                .collect(),
            recovery_id: record.recovery_id.map(|id| hex_32(&id.0)),
            port: record.port,
            last_ip: record.last_ip,
            expires_at_ms: record.expires_at_ms,
        }
    }

    fn into_record(self) -> anyhow::Result<LeaseRecord> {
        anyhow::ensure!(
            self.token_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "Invalid token fingerprint"
        );
        Ok(LeaseRecord {
            token_id: TokenId(parse_hex_32(&self.token_id)?),
            retired_token_ids: self
                .retired_token_ids
                .into_iter()
                .chain(self.retired_token_id)
                .map(|id| parse_hex_32(&id).map(TokenId))
                .collect::<anyhow::Result<Vec<_>>>()?,
            recovery_id: self
                .recovery_id
                .map(|id| parse_hex_32(&id).map(TokenId))
                .transpose()?,
            port: self.port,
            last_ip: self.last_ip,
            expires_at_ms: self.expires_at_ms,
        })
    }
}

fn hex_32(bytes: &[u8; 32]) -> String {
    let mut result = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn parse_hex_32(hex: &str) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        hex.len() == 64 && hex.is_ascii(),
        "Expected 64 hex characters"
    );
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn sync_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::TokenId;

    #[test]
    fn saves_fingerprint_and_restores_unexpired_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gamenet-state.json");
        let token = [42u8; 32];
        let token_id = TokenId::from_token(&token);
        let (store, mut table) = LeaseStore::load_or_create(&path, 1_000).unwrap();
        let ip = "192.0.2.1".parse().unwrap();
        let port = table.candidate_ports(token_id, ip, 1_000).unwrap()[0];
        table.activate(token_id, ip, port, 1_000).unwrap();
        store.save(&table.snapshot(1_000)).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let raw_hex = "2a".repeat(32);
        assert!(!String::from_utf8_lossy(&bytes).contains(&raw_hex));
        let (_, restored) = LeaseStore::load_or_create(&path, 2_000).unwrap();
        assert_eq!(restored.grace_port(token_id), Some(port));
    }

    #[test]
    fn rejects_malformed_duplicate_and_oversized_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gamenet-state.json");
        for content in [
            "not json".to_string(),
            "{\"version\":3,\"leases\":[]}".to_string(),
            format!(
                "{{\"version\":2,\"leases\":[{{\"token_id\":\"{}\",\"port\":10000,\"last_ip\":null,\"expires_at_ms\":999999}},{{\"token_id\":\"{}\",\"port\":10000,\"last_ip\":null,\"expires_at_ms\":999999}}]}}",
                "11".repeat(32),
                "22".repeat(32)
            ),
            "x".repeat(1_048_577),
        ] {
            std::fs::write(&path, content).unwrap();
            assert!(LeaseStore::load_or_create(&path, 1_000).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_fingerprint_even_if_first_lease_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gamenet-state.json");
        let token_id = "11".repeat(32);
        let content = format!(
            "{{\"version\":2,\"leases\":[{{\"token_id\":\"{token_id}\",\"port\":10000,\"last_ip\":null,\"expires_at_ms\":1}},{{\"token_id\":\"{token_id}\",\"port\":10001,\"last_ip\":null,\"expires_at_ms\":999999}}]}}"
        );
        std::fs::write(&path, content).unwrap();
        assert!(LeaseStore::load_or_create(&path, 1_000).is_err());
    }

    #[test]
    fn migrates_legacy_reservations_with_owner_only_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gamenet-state.json");
        let raw_hex = "2a".repeat(32);
        let legacy = format!("{{\"token_ports\":[[\"{}\",10000]]}}", raw_hex);
        std::fs::write(&path, &legacy).unwrap();

        let (_, table) = LeaseStore::load_or_create(&path, 1_000).unwrap();
        assert_eq!(
            table.grace_port(TokenId::from_token(&[42; 32])),
            Some(10000)
        );
        assert!(!std::fs::read_to_string(&path).unwrap().contains(&raw_hex));
        let backup = dir.path().join("gamenet-state.json.legacy-backup");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), legacy);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn migration_recovers_after_complete_or_partial_backup() {
        for partial in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("gamenet-state.json");
            let backup = dir.path().join("gamenet-state.json.legacy-backup");
            let legacy = format!("{{\"token_ports\":[[\"{}\",10000]]}}", "2a".repeat(32));
            std::fs::write(&path, &legacy).unwrap();
            if partial {
                std::fs::write(&backup, &legacy.as_bytes()[..20]).unwrap();
            } else {
                std::fs::write(&backup, &legacy).unwrap();
            }

            let (_, table) = LeaseStore::load_or_create(&path, 1_000).unwrap();
            assert_eq!(
                table.grace_port(TokenId::from_token(&[42; 32])),
                Some(10000)
            );
            assert_eq!(std::fs::read_to_string(&backup).unwrap(), legacy);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn failed_save_does_not_create_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("state.json");
        let (store, table) = LeaseStore::load_or_create(&path, 1_000).unwrap();
        assert!(store.save(&table.snapshot(1_000)).is_err());
        assert!(!path.exists());
    }
}
