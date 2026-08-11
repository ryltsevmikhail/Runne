
fn expected_profile() -> Result<ProtectedRuntimeProfileV1, ProtectedBundledRuntimeError> {
    let profile_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::ProfileHashMismatch,
        ))?;
    let capabilities = REQUIRED_RUNTIME_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        gocode_runtime_client::EXPECTED_BUNDLE_ID,
        profile_hash,
        ordered_capability_digest(&capabilities),
    )
    .map_err(Into::into)
}

fn ordered_capability_digest(capabilities: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-runtime/capability-digest/v1\0");
    hasher.update(
        u32::try_from(capabilities.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for capability in capabilities {
        let bytes = capability.as_bytes();
        hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

fn unix_millis() -> Result<u64, ProtectedBundledRuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(ProtectedBundledRuntimeError::InvalidState)
}

#[cfg(unix)]
fn read_frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, ProtectedBundledRuntimeError> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|error| map_channel_error(&error))?;
    let payload_length = u32::from_be_bytes(prefix) as usize;
    if payload_length == 0 || payload_length > MAX_FRAME_PAYLOAD_BYTES {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    let total =
        payload_length
            .checked_add(4)
            .ok_or(ProtectedBundledRuntimeError::LaunchAuthority(
                LaunchAuthorityError::InvalidContract,
            ))?;
    let mut frame = Zeroizing::new(vec![0_u8; total]);
    frame[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|error| map_channel_error(&error))?;
    Ok(frame)
}

#[cfg(unix)]
fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), ProtectedBundledRuntimeError> {
    if frame.len() < 5 || frame.len() > MAX_FRAME_PAYLOAD_BYTES + 4
        || u32::from_be_bytes(frame[..4].try_into().unwrap_or([0; 4])) as usize != frame.len() - 4
    {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|error| map_channel_error(&error))
}

#[cfg(unix)]
fn map_channel_error(error: &std::io::Error) -> ProtectedBundledRuntimeError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        ProtectedBundledRuntimeError::ReadinessTimeout
    } else {
        ProtectedBundledRuntimeError::ProtectedChannelUnavailable
    }
}

#[cfg(unix)]
fn validate_executable_path(path: &Path) -> Result<PathBuf, ProtectedBundledRuntimeError> {
    if !path.is_absolute() {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    let original = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    if original.file_type().is_symlink() || !original.is_file() {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || metadata.len() == 0 || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    validate_secure_directory_chain(&canonical)?;
    Ok(canonical)
}

#[cfg(unix)]
fn validate_secure_directory_chain(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    let effective_uid = rustix::process::geteuid().as_raw();
    let mut child_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    let mut directory = path
        .parent()
        .ok_or(ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    loop {
        let metadata = std::fs::symlink_metadata(directory)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        {
            return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
        }
        if mode & 0o022 != 0
            && (mode & 0o1000 == 0
                || (child_metadata.uid() != 0 && child_metadata.uid() != effective_uid))
        {
            return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
        }
        child_metadata = metadata;
        let Some(parent) = directory.parent() else {
            break;
        };
        if parent == directory {
            break;
        }
        directory = parent;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_source_file(file: &File) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || metadata.len() == 0 || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_staged_executable(
    path: &Path,
    trusted_source: &ExecutableIdentityV1,
) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o500
        || metadata.nlink() != 1
        || metadata.len() != trusted_source.byte_length()
    {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    let identity = ExecutableIdentityV1::measure(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if identity.executable_sha256() != trusted_source.executable_sha256()
        || identity.byte_length() != trusted_source.byte_length()
    {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_owner_private_directory(path: &Path) -> Result<PathBuf, ProtectedBundledRuntimeError> {
    if !path.is_absolute() {
        return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        }
        Err(_) => return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable),
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
    }
    std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    validate_owner_private_directory(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    Ok(canonical)
}

#[cfg(unix)]
fn validate_owner_private_directory(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    Ok(())
}
