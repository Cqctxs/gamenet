use std::path::{Path, PathBuf};

pub type TunnelToken = [u8; 32];

fn identity_path() -> PathBuf {
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join(".config").join("gamenet").join("identity.bin")
}

pub fn load_or_create() -> anyhow::Result<TunnelToken> {
    load_or_create_at(&identity_path())
}

pub fn load_or_create_at(path: &Path) -> anyhow::Result<TunnelToken> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        bytes.try_into().map_err(|_| {
            anyhow::anyhow!("Identity file corrupt: expected 32 bytes at {:?}", path)
        })
    } else {
        let mut token = [0u8; 32];
        getrandom::getrandom(&mut token)
            .map_err(|e| anyhow::anyhow!("Failed to generate token: {}", e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &token)?;
        Ok(token)
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
        std::env::temp_dir().join(format!("gamenet-id-{}-{}.bin", suffix, ns))
    }

    #[test]
    fn creates_token_on_fresh_path() {
        let path = temp_path("fresh");
        let token = load_or_create_at(&path).unwrap();
        assert_eq!(token.len(), 32);
        assert!(path.exists());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn loads_same_token_on_second_call() {
        let path = temp_path("reload");
        let token1 = load_or_create_at(&path).unwrap();
        let token2 = load_or_create_at(&path).unwrap();
        assert_eq!(token1, token2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn tokens_are_not_all_zeros() {
        let path = temp_path("nonzero");
        let token = load_or_create_at(&path).unwrap();
        assert_ne!(token, [0u8; 32]);
        std::fs::remove_file(&path).ok();
    }
}
