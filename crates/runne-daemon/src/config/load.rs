/// Loads the fixed external source, treating its absence as no selection.
pub fn load_external_config() -> Result<ConfigurationSnapshot, DaemonError> {
    load_external_config_at(&external_config_path())
}

/// Snapshot read from the fixed owner-private source through the checked loader.
/// The private field prevents callers from minting source-verification evidence.
pub(crate) struct VerifiedFixedExternalConfig {
    snapshot: ConfigurationSnapshot,
}

impl VerifiedFixedExternalConfig {
    pub(crate) const fn snapshot(&self) -> &ConfigurationSnapshot {
        &self.snapshot
    }

    #[cfg(test)]
    pub(crate) fn from_test_snapshot(snapshot: ConfigurationSnapshot) -> Self {
        Self { snapshot }
    }
}

pub(crate) fn load_verified_fixed_external_config()
-> Result<VerifiedFixedExternalConfig, DaemonError> {
    Ok(VerifiedFixedExternalConfig {
        snapshot: load_external_config()?,
    })
}

/// Loads an injected fixed external source for native-entry tests.
pub fn load_external_config_at(path: &Path) -> Result<ConfigurationSnapshot, DaemonError> {
    match fs::symlink_metadata(path) {
        Ok(_) => load_config(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => load_config(None),
        Err(error) => Err(DaemonError::Io(error)),
    }
}

fn read_explicit_config(path: &Path) -> Result<String, DaemonError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !owner_private_config_metadata(
            metadata.is_file(),
            metadata.uid(),
            metadata.permissions().mode(),
            rustix::process::geteuid().as_raw(),
        ) {
            return Err(DaemonError::Config(
                "external config is not owner-private".into(),
            ));
        }
        if metadata.len() > MAX_EXTERNAL_CONFIG_BYTES {
            return Err(DaemonError::Config(
                "external config exceeds size limit".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_EXTERNAL_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_EXTERNAL_CONFIG_BYTES {
            return Err(DaemonError::Config(
                "external config exceeds size limit".into(),
            ));
        }
        String::from_utf8(bytes)
            .map_err(|_| DaemonError::Config("external config is not UTF-8".into()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(DaemonError::Config(
            "external config validation is unsupported".into(),
        ))
    }
}

#[cfg(unix)]
fn owner_private_config_metadata(
    is_file: bool,
    owner: u32,
    mode: u32,
    expected_owner: u32,
) -> bool {
    is_file && owner == expected_owner && mode & 0o077 == 0
}

#[cfg(all(test, unix))]
#[path = "load_security_tests.rs"]
mod security_tests;
