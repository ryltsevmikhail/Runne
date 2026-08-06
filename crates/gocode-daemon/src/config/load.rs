
/// Loads the fixed external source, treating its absence as no selection.
pub fn load_external_config() -> Result<ConfigurationSnapshot, DaemonError> {
    load_external_config_at(&external_config_path())
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
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
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
