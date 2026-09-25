use std::path::{Path, PathBuf};
use std::{fs, io::Write};

use tempfile::NamedTempFile;

#[cfg(windows)]
mod windows_acl;
#[cfg(windows)]
use windows_acl::set_owner_only;

pub type TunnelToken = [u8; 32];

pub fn identity_path() -> PathBuf {
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join(".config").join("gamenet").join("identity.bin")
}

fn recovery_path() -> PathBuf {
    identity_path().with_file_name("recovery.bin")
}

pub fn load_or_create_recovery() -> anyhow::Result<TunnelToken> {
    load_or_create_recovery_at(&recovery_path())
}

pub fn load_or_create_recovery_at(path: &Path) -> anyhow::Result<TunnelToken> {
    load_or_create_at(path)
}

pub fn read_recovery() -> anyhow::Result<TunnelToken> {
    read_recovery_at(&recovery_path())
}

pub fn read_recovery_at(path: &Path) -> anyhow::Result<TunnelToken> {
    read_existing(path)
}

pub fn store_recovery(secret: &TunnelToken) -> anyhow::Result<()> {
    store_recovery_at(&recovery_path(), secret)
}

pub fn store_recovery_at(path: &Path, secret: &TunnelToken) -> anyhow::Result<()> {
    if create_new_private(path, secret)? {
        return Ok(());
    }
    if read_existing(path)? == *secret {
        return Ok(());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)?;
    #[cfg(any(unix, windows))]
    set_owner_only(temporary.path())?;
    temporary.write_all(secret)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn format_recovery_code(secret: &TunnelToken) -> String {
    let mut code = String::with_capacity(64);
    for byte in secret {
        use std::fmt::Write as _;
        write!(code, "{byte:02x}").expect("writing to String cannot fail");
    }
    code
}

pub fn recovery_fingerprint(secret: &TunnelToken) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, secret)
        .as_ref()
        .try_into()
        .expect("SHA-256 has 32 bytes")
}

pub fn parse_recovery_code(code: &str) -> anyhow::Result<TunnelToken> {
    let code = code.trim();
    anyhow::ensure!(
        code.len() == 64 && code.is_ascii(),
        "Recovery code must be 64 hex characters"
    );
    let mut secret = [0u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&code[index * 2..index * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("Recovery code contains a non-hex character"))?;
    }
    Ok(secret)
}

pub struct PendingRecovery {
    path: PathBuf,
    pending_path: PathBuf,
    old_token: Option<TunnelToken>,
    new_token: TunnelToken,
}

impl PendingRecovery {
    pub fn new_token(&self) -> TunnelToken {
        self.new_token
    }

    pub fn finish(self) -> anyhow::Result<()> {
        let current = match fs::symlink_metadata(&self.path) {
            Ok(_) => Some(read_existing(&self.path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            current == self.old_token,
            "Identity changed during recovery"
        );
        anyhow::ensure!(
            read_existing(&self.pending_path)? == self.new_token,
            "Pending identity changed during recovery"
        );
        fs::rename(&self.pending_path, &self.path)?;
        #[cfg(unix)]
        fs::File::open(self.path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(())
    }
}

pub fn prepare_recovery() -> anyhow::Result<PendingRecovery> {
    prepare_recovery_at(&identity_path())
}

pub fn prepare_recovery_at(path: &Path) -> anyhow::Result<PendingRecovery> {
    let old_token = match fs::symlink_metadata(path) {
        Ok(_) => Some(read_existing(path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let pending_path = pending_path(path)?;
    let new_token = load_or_create_at(&pending_path)?;
    anyhow::ensure!(
        Some(new_token) != old_token,
        "Pending identity equals current identity"
    );
    Ok(PendingRecovery {
        path: path.to_owned(),
        pending_path,
        old_token,
        new_token,
    })
}

fn pending_path(path: &Path) -> anyhow::Result<PathBuf> {
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Identity path has no file name"))?;
    Ok(path.with_file_name(format!("{}.pending", filename.to_string_lossy())))
}

pub fn load_or_create() -> anyhow::Result<TunnelToken> {
    load_or_create_at(&identity_path())
}

pub fn load_or_create_at(path: &Path) -> anyhow::Result<TunnelToken> {
    match fs::symlink_metadata(path) {
        Ok(_) => return read_existing(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token)
        .map_err(|error| anyhow::anyhow!("Failed to generate token: {error}"))?;
    if create_new_private(path, &token)? {
        Ok(token)
    } else {
        read_existing(path)
    }
}

pub struct PendingRotation {
    path: PathBuf,
    pending_path: PathBuf,
    old_token: TunnelToken,
    new_token: TunnelToken,
}

impl PendingRotation {
    pub fn old_token(&self) -> TunnelToken {
        self.old_token
    }
    pub fn new_token(&self) -> TunnelToken {
        self.new_token
    }

    pub fn finish(self) -> anyhow::Result<()> {
        anyhow::ensure!(
            read_existing(&self.path)? == self.old_token,
            "Identity changed during rotation"
        );
        anyhow::ensure!(
            read_existing(&self.pending_path)? == self.new_token,
            "Pending identity changed during rotation"
        );
        fs::rename(&self.pending_path, &self.path)?;
        #[cfg(unix)]
        fs::File::open(self.path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(())
    }
}

pub fn prepare_rotation() -> anyhow::Result<PendingRotation> {
    prepare_rotation_at(&identity_path())
}

pub fn prepare_rotation_at(path: &Path) -> anyhow::Result<PendingRotation> {
    let old_token = read_existing(path)?;
    let pending_path = pending_path(path)?;
    let new_token = match fs::symlink_metadata(&pending_path) {
        Ok(_) => read_existing(&pending_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut candidate = [0u8; 32];
            getrandom::getrandom(&mut candidate)
                .map_err(|error| anyhow::anyhow!("Failed to generate token: {error}"))?;
            if create_new_private(&pending_path, &candidate)? {
                candidate
            } else {
                read_existing(&pending_path)?
            }
        }
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        old_token != new_token,
        "Pending identity equals current identity"
    );
    Ok(PendingRotation {
        path: path.to_owned(),
        pending_path,
        old_token,
        new_token,
    })
}

fn create_new_private(path: &Path, token: &TunnelToken) -> anyhow::Result<bool> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    #[cfg(any(unix, windows))]
    set_owner_only(temporary.path())?;
    temporary.write_all(token)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => {
            #[cfg(unix)]
            fs::File::open(parent)?.sync_all()?;
            Ok(true)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.error.into()),
    }
}

fn read_existing(path: &Path) -> anyhow::Result<TunnelToken> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "Identity path is not a regular file"
    );
    #[cfg(any(unix, windows))]
    set_owner_only(path)?;
    let bytes = fs::read(path)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Identity file corrupt: expected 32 bytes at {:?}", path))
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
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
    fn backup_code_round_trips_and_rejects_bad_input() {
        let secret = [0xab; 32];
        let code = format_recovery_code(&secret);
        assert_eq!(code.len(), 64);
        assert_eq!(parse_recovery_code(&code).unwrap(), secret);
        assert!(parse_recovery_code("abcd").is_err());
        assert!(parse_recovery_code(&"z".repeat(64)).is_err());
    }

    #[test]
    fn recovery_secret_is_separate_and_pending_identity_survives_retry() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.bin");
        let recovery = dir.path().join("recovery.bin");
        let old = load_or_create_at(&identity).unwrap();
        let secret = load_or_create_recovery_at(&recovery).unwrap();
        assert_ne!(old, secret);
        assert_eq!(read_recovery_at(&recovery).unwrap(), secret);
        let pending = prepare_recovery_at(&identity).unwrap();
        let new = pending.new_token();
        assert_eq!(prepare_recovery_at(&identity).unwrap().new_token(), new);
        assert_eq!(load_or_create_at(&identity).unwrap(), old);
        pending.finish().unwrap();
        assert_eq!(load_or_create_at(&identity).unwrap(), new);
        assert_eq!(read_recovery_at(&recovery).unwrap(), secret);
    }

    #[test]
    fn backup_code_can_replace_wrong_local_recovery_file_after_relay_ack() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.bin");
        store_recovery_at(&path, &[1; 32]).unwrap();
        store_recovery_at(&path, &[2; 32]).unwrap();
        assert_eq!(read_recovery_at(&path).unwrap(), [2; 32]);
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

    #[cfg(unix)]
    #[test]
    fn repairs_world_readable_existing_identity() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        std::fs::write(&path, [7; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(load_or_create_at(&path).unwrap(), [7; 32]);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_identity_file() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("other.bin");
        let path = dir.path().join("identity.bin");
        std::fs::write(&target, [9; 32]).unwrap();
        symlink(&target, &path).unwrap();

        assert!(load_or_create_at(&path).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), [9; 32]);
    }

    #[test]
    fn interrupted_rotation_reuses_pending_token_and_replaces_identity_only_after_ack() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        let old = load_or_create_at(&path).unwrap();
        let first = prepare_rotation_at(&path).unwrap();
        assert_eq!(first.old_token(), old);
        assert_ne!(first.new_token(), old);
        assert_eq!(load_or_create_at(&path).unwrap(), old);

        let retry = prepare_rotation_at(&path).unwrap();
        assert_eq!(retry.new_token(), first.new_token());
        retry.finish().unwrap();
        assert_eq!(load_or_create_at(&path).unwrap(), first.new_token());
        assert!(!path.with_extension("bin.pending").exists());
    }

    #[test]
    fn simultaneous_first_use_gets_one_complete_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        let ready = std::sync::Arc::new(std::sync::Barrier::new(12));
        let workers: Vec<_> = (0..12)
            .map(|_| {
                let path = path.clone();
                let ready = std::sync::Arc::clone(&ready);
                std::thread::spawn(move || {
                    ready.wait();
                    load_or_create_at(&path).unwrap()
                })
            })
            .collect();
        let tokens: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(tokens.iter().all(|token| *token == tokens[0]));
        assert_eq!(std::fs::read(path).unwrap(), tokens[0]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_has_one_noninherited_acl_entry() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, SE_DACL_PROTECTED,
        };

        fn assert_private(path: &Path) {
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut acl = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let status = unsafe {
                GetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut acl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                )
            };
            assert_eq!(status, 0);
            let mut control = 0;
            let mut revision = 0;
            let result =
                unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
            assert_ne!(result, 0);
            assert_ne!(control & SE_DACL_PROTECTED, 0);
            assert_eq!(unsafe { (*acl).AceCount }, 1);
            unsafe { LocalFree(descriptor) };
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        load_or_create_at(&path).unwrap();
        assert_private(&path);
        prepare_rotation_at(&path).unwrap();
        assert_private(&path.with_extension("bin.pending"));
        let recovery = dir.path().join("recovery.bin");
        load_or_create_recovery_at(&recovery).unwrap();
        assert_private(&recovery);
        store_recovery_at(&recovery, &[42; 32]).unwrap();
        assert_private(&recovery);
        let older = dir.path().join("older.bin");
        std::fs::write(&older, [7; 32]).unwrap();
        load_or_create_at(&older).unwrap();
        assert_private(&older);
    }
}
