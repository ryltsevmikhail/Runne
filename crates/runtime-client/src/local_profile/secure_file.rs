pub fn read_bootstrap_secret(path: &Path) -> Result<[u8; 32], LocalRuntimeConnectError> {
    let bytes = read_secure_file(path, 32, LocalProfileError::InvalidCredential)
        .map_err(|_| incompatible())?;
    bytes.try_into().map_err(|_| incompatible())
}

const fn incompatible() -> LocalRuntimeConnectError {
    LocalRuntimeConnectError::Api(crate::RuntimeApiError::new(
        crate::RuntimeApiErrorKind::Incompatible,
    ))
}

fn read_secure_file(
    path: &Path,
    maximum_bytes: usize,
    invalid_content: LocalProfileError,
) -> Result<Vec<u8>, LocalProfileError> {
    let mut file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalProfileError::Unavailable)?;
    if !metadata.is_file() {
        return Err(invalid_content);
    }
    ensure_owner_only(&metadata)?;
    let maximum_length =
        u64::try_from(maximum_bytes).map_err(|_| LocalProfileError::Unavailable)?;
    if metadata.len() > maximum_length {
        return Err(invalid_content);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| LocalProfileError::Unavailable)?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|_| LocalProfileError::Unavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(invalid_content);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, LocalProfileError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| LocalProfileError::Unavailable)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, LocalProfileError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| LocalProfileError::Unavailable)
}

#[cfg(unix)]
fn ensure_owner_only(metadata: &std::fs::Metadata) -> Result<(), LocalProfileError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let effective_user = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective_user || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(LocalProfileError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_: &std::fs::Metadata) -> Result<(), LocalProfileError> {
    Err(LocalProfileError::InsecurePermissions)
}
