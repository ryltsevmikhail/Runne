// ── Lockfile open/create with platform no-follow safety ────────────────

/// Open or atomically create a lock file with platform-appropriate no-follow
/// guarantees.
///
/// - If the file exists: open for read+write, verify it is a regular file
///   (not a symlink/reparse point).
/// - If the file does not exist: `create_new` to atomically ensure we're the
///   sole creator.
fn open_or_create_lockfile(path: &Path) -> Result<std::fs::File, DaemonError> {
    match create_no_follow(path) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = open_existing_no_follow(path)?;
            verify_regular_file(&file, path)?;
            Ok(file)
        }
        Err(e) => Err(DaemonError::Lock(format!(
            "failed to create lock file {path}: {e}",
            path = path.display()
        ))),
    }
}

/// Open existing lock file with no-follow, read+write.
fn open_existing_no_follow(path: &Path) -> Result<std::fs::File, DaemonError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(false);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW_VAL | O_CLOEXEC);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = opts.open(path).map_err(|e| {
        DaemonError::Lock(format!(
            "failed to open existing lock file {path}: {e}",
            path = path.display()
        ))
    })?;

    #[cfg(windows)]
    {
        verify_not_reparse_point(&file, path)?;
    }

    Ok(file)
}

/// Atomically create a new lock file with no-follow.
fn create_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[allow(clippy::useless_conversion)]
        opts.custom_flags(if O_NOFOLLOW_VAL != 0 {
            O_NOFOLLOW_VAL | O_CLOEXEC
        } else {
            O_CLOEXEC
        });
        let file = opts.open(path)?;
        // Set permissions to 0600 on new file
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        let _ = file.set_permissions(perm);
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        opts.open(path)
    }
}

// ── File verification ─────────────────────────────────────────────────

/// Verify `file` is a regular file.
fn verify_regular_file(file: &std::fs::File, path: &Path) -> Result<(), DaemonError> {
    let meta = file.metadata().map_err(|e| {
        DaemonError::Lock(format!(
            "failed to read metadata of {path}: {e}",
            path = path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(DaemonError::Lock(format!(
            "lock file {path} is not a regular file",
            path = path.display()
        )));
    }
    Ok(())
}

/// On Windows, verify the opened file is NOT a reparse point.
#[cfg(windows)]
fn verify_not_reparse_point(file: &std::fs::File, path: &Path) -> Result<(), DaemonError> {
    use std::os::windows::fs::MetadataExt;
    let meta = file.metadata().map_err(|e| {
        DaemonError::Lock(format!(
            "failed to read metadata of {path}: {e}",
            path = path.display()
        ))
    })?;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DaemonError::Lock(format!(
            "lock file {path} is a reparse point — rejected",
            path = path.display()
        )));
    }
    Ok(())
}
