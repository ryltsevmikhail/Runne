#[cfg(unix)]
fn validate_owner_private_recovery_files(db_path: &Path) -> Result<(), SchemaOpenDiagnostic> {
    use std::os::unix::fs::MetadataExt as _;

    if !db_path.is_absolute() || !path_is_safe(db_path) {
        return Err(SchemaOpenDiagnostic::SidecarPresent);
    }
    let daemon_dir = db_path
        .parent()
        .ok_or(SchemaOpenDiagnostic::FileIdentityUncertain)?;
    let runtime_root = daemon_dir
        .parent()
        .ok_or(SchemaOpenDiagnostic::FileIdentityUncertain)?;
    let root_metadata = fs::symlink_metadata(runtime_root)
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.mode() & 0o022 != 0
    {
        return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
    }
    let owner = root_metadata.uid();
    let daemon_metadata = fs::symlink_metadata(daemon_dir)
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
    if daemon_metadata.file_type().is_symlink()
        || !daemon_metadata.is_dir()
        || daemon_metadata.uid() != owner
        || daemon_metadata.mode() & 0o077 != 0
    {
        return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
    }

    for path in [
        db_path.to_path_buf(),
        sidecar_path(db_path, "-wal"),
        sidecar_path(db_path, "-shm"),
    ] {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if path != db_path && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(_) => return Err(SchemaOpenDiagnostic::FileIdentityUncertain),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_owner_private_recovery_files(db_path: &Path) -> Result<(), SchemaOpenDiagnostic> {
    if !db_path.is_absolute() || !path_is_safe(db_path) {
        return Err(SchemaOpenDiagnostic::SidecarPresent);
    }
    let daemon_dir = db_path
        .parent()
        .ok_or(SchemaOpenDiagnostic::FileIdentityUncertain)?;
    let runtime_root = daemon_dir
        .parent()
        .ok_or(SchemaOpenDiagnostic::FileIdentityUncertain)?;
    for directory in [runtime_root, daemon_dir] {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
        }
        secure_dir_permissions(directory)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
    }
    for path in [
        db_path.to_path_buf(),
        sidecar_path(db_path, "-wal"),
        sidecar_path(db_path, "-shm"),
    ] {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if path != db_path && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(_) => return Err(SchemaOpenDiagnostic::FileIdentityUncertain),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
        }
        let snapshot = runne_windows_native_handle::inspect_regular_file(&path)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        if snapshot.link_count() != 1 {
            return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
        }
        secure_file_permissions(&path)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
    }
    Ok(())
}

fn existing_sidecar_present(db_path: &Path) -> bool {
    ["-wal", "-shm"]
        .into_iter()
        .any(|suffix| sidecar_path(db_path, suffix).exists())
}

fn immutable_read_only_uri(path: &Path) -> Result<String, SchemaOpenDiagnostic> {
    let text = path
        .as_os_str()
        .to_str()
        .ok_or(SchemaOpenDiagnostic::UnsafePath)?;
    let mut uri = String::with_capacity(text.len() + 32);
    uri.push_str("file:");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}")
                .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}
