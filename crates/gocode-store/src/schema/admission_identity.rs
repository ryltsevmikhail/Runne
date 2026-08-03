#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    file: u64,
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity(same_file::Handle);

fn file_identity(path: &Path) -> Result<FileIdentity, SchemaOpenDiagnostic> {
    if fs::symlink_metadata(path)
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?
        .file_type()
        .is_symlink()
    {
        return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let metadata =
            fs::metadata(path).map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        Ok(FileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        same_file::Handle::from_path(path)
            .map(FileIdentity)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
    }
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct RecoveryFileSet {
    database: FileIdentity,
    wal: Option<FileIdentity>,
    shm: Option<FileIdentity>,
}

#[cfg(unix)]
fn owner_private_recovery_file_set(
    db_path: &Path,
) -> Result<RecoveryFileSet, SchemaOpenDiagnostic> {
    validate_owner_private_recovery_files(db_path)?;
    Ok(RecoveryFileSet {
        database: file_identity(db_path)?,
        wal: optional_file_identity(&sidecar_path(db_path, "-wal"))?,
        shm: optional_file_identity(&sidecar_path(db_path, "-shm"))?,
    })
}

#[cfg(unix)]
fn recovery_file_set_unchanged(
    db_path: &Path,
    expected: &RecoveryFileSet,
) -> Result<bool, SchemaOpenDiagnostic> {
    validate_owner_private_recovery_files(db_path)?;
    let current = RecoveryFileSet {
        database: file_identity(db_path)?,
        wal: optional_file_identity(&sidecar_path(db_path, "-wal"))?,
        shm: optional_file_identity(&sidecar_path(db_path, "-shm"))?,
    };
    // SQLite may create WAL/SHM while opening a WAL-mode database READ_WRITE,
    // before it accepts `query_only`, or remove stale crash sidecars after it
    // has consumed them. The private directory remains the owner boundary;
    // sidecars that remain present must still retain their identities.
    Ok(current.database == expected.database
        && optional_identity_matches(&expected.wal, &current.wal)
        && optional_identity_matches(&expected.shm, &current.shm))
}

#[cfg(unix)]
fn optional_file_identity(path: &Path) -> Result<Option<FileIdentity>, SchemaOpenDiagnostic> {
    match fs::symlink_metadata(path) {
        Ok(_) => match file_identity(path) {
            Ok(identity) => Ok(Some(identity)),
            Err(SchemaOpenDiagnostic::FileIdentityUncertain) if !path.exists() => Ok(None),
            Err(error) => Err(error),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SchemaOpenDiagnostic::FileIdentityUncertain),
    }
}

#[cfg(unix)]
fn optional_identity_matches(
    expected: &Option<FileIdentity>,
    actual: &Option<FileIdentity>,
) -> bool {
    match (expected, actual) {
        (Some(expected), Some(actual)) => expected == actual,
        (Some(_), None) | (None, _) => true,
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

fn path_is_safe(path: &Path) -> bool {
    !path.to_string_lossy().contains(['?', '#', '%'])
}
