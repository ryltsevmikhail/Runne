// Windows filesystem and frame helpers for protected bundled activation.

fn read_frame(
    stream: &mut File,
) -> Result<Zeroizing<Vec<u8>>, ProtectedBundledRuntimeError> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(|error| map_channel_error(&error))?;
    let payload_length = u32::from_be_bytes(prefix) as usize;
    if payload_length == 0 || payload_length > MAX_FRAME_PAYLOAD_BYTES {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    let total = payload_length.checked_add(4).ok_or(
        ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract),
    )?;
    let mut frame = Zeroizing::new(vec![0_u8; total]);
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).map_err(|error| map_channel_error(&error))?;
    Ok(frame)
}

fn write_frame(
    stream: &mut File,
    frame: &[u8],
) -> Result<(), ProtectedBundledRuntimeError> {
    if frame.len() < 5
        || frame.len() > MAX_FRAME_PAYLOAD_BYTES + 4
        || u32::from_be_bytes(frame[..4].try_into().unwrap_or([0; 4])) as usize
            != frame.len() - 4
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

fn map_channel_error(error: &std::io::Error) -> ProtectedBundledRuntimeError {
    if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) {
        ProtectedBundledRuntimeError::ReadinessTimeout
    } else {
        ProtectedBundledRuntimeError::ProtectedChannelUnavailable
    }
}

fn validate_executable_path(path: &Path) -> Result<PathBuf, ProtectedBundledRuntimeError> {
    if !path.is_absolute() {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    let original = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    if original.file_type().is_symlink() || !original.is_file() || original.len() == 0 {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
    }
    validate_secure_directory_chain(&canonical)?;
    Ok(canonical)
}

fn validate_secure_directory_chain(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    let mut directory = path
        .parent()
        .ok_or(ProtectedBundledRuntimeError::ExecutableUnavailable)?;
    loop {
        let metadata = std::fs::symlink_metadata(directory)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProtectedBundledRuntimeError::ExecutableUnavailable);
        }
        let Some(parent) = directory.parent() else { break };
        if parent == directory { break; }
        directory = parent;
    }
    Ok(())
}

fn validate_trusted_source_file(file: &File) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    Ok(())
}

fn validate_staged_executable(
    path: &Path,
    trusted_source: &ExecutableIdentityV1,
) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
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
    validate_private_path(path)
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    Ok(())
}

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
    validate_private_path(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    validate_owner_private_directory(&canonical)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    Ok(canonical)
}

fn validate_owner_private_directory(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    validate_private_path(path)?;
    Ok(())
}

fn validate_owner_private_file(file: &File) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if !metadata.is_file() {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(_: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    Ok(())
}
