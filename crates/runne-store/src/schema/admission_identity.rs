#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    file: u64,
}

#[cfg(unix)]
fn descriptor_identity(file: &fs::File) -> Result<FileIdentity, SchemaOpenDiagnostic> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
    if !metadata.is_file() {
        return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
    }
    Ok(FileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity(runne_sqlite_native_identity::DatabaseFileIdentity);

#[cfg(windows)]
fn descriptor_identity(file: &fs::File) -> Result<FileIdentity, SchemaOpenDiagnostic> {
    runne_sqlite_native_identity::file_database_identity(file)
        .map(FileIdentity)
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
}

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
        runne_windows_native_handle::inspect_regular_file(path)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        runne_sqlite_native_identity::path_database_identity(path)
            .map(FileIdentity)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
    }
}

#[cfg(any(unix, windows))]
struct RetainedFileIdentity {
    path: PathBuf,
    file: fs::File,
    identity: FileIdentity,
}

#[cfg(any(unix, windows))]
impl RetainedFileIdentity {
    fn from_file(path: &Path, file: fs::File) -> Result<Self, SchemaOpenDiagnostic> {
        let identity = descriptor_identity(&file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
        })
    }

    fn open(path: &Path) -> Result<Self, SchemaOpenDiagnostic> {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            #[cfg(target_os = "linux")]
            // O_PATH anchors support metadata checks without closing an fd
            // that would release SQLite's process-wide POSIX locks.
            options.custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW);
            #[cfg(not(target_os = "linux"))]
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        Self::from_file(path, file)
    }

    fn unchanged(&self) -> Result<bool, SchemaOpenDiagnostic> {
        Ok(descriptor_identity(&self.file)? == self.identity
            && file_identity(&self.path)? == self.identity)
    }
}

#[cfg(any(unix, windows))]
struct ConnectionIdentityGuard {
    database: RetainedFileIdentity,
    wal: Option<RetainedFileIdentity>,
    shm: Option<RetainedFileIdentity>,
    owner_private: bool,
}

#[cfg(any(unix, windows))]
impl ConnectionIdentityGuard {
    fn main(path: &Path) -> Result<Self, SchemaOpenDiagnostic> {
        Ok(Self {
            database: RetainedFileIdentity::open(path)?,
            wal: None,
            shm: None,
            owner_private: false,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn from_created(path: &Path, file: fs::File) -> Result<Self, SchemaOpenDiagnostic> {
        Ok(Self {
            database: RetainedFileIdentity::from_file(path, file)?,
            wal: None,
            shm: None,
            owner_private: false,
        })
    }

    fn owner_private(path: &Path) -> Result<Self, SchemaOpenDiagnostic> {
        validate_owner_private_recovery_files(path)?;
        Ok(Self {
            database: RetainedFileIdentity::open(path)?,
            wal: retain_optional(&sidecar_path(path, "-wal"))?,
            shm: retain_optional(&sidecar_path(path, "-shm"))?,
            owner_private: true,
        })
    }

    fn verify(&self, connection: &Connection) -> SqliteResult<()> {
        if !self.database.unchanged().map_err(diagnostic_error)?
            || !sqlite_main_matches_expected(connection, &self.database.identity)
        {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        if self.owner_private {
            validate_owner_private_recovery_files(&self.database.path)
                .map_err(diagnostic_error)?;
            if !optional_retained_unchanged(&self.wal, &sidecar_path(&self.database.path, "-wal"))?
                || !optional_retained_unchanged(
                    &self.shm,
                    &sidecar_path(&self.database.path, "-shm"),
                )?
            {
                return Err(diagnostic_error(
                    SchemaOpenDiagnostic::FileIdentityUncertain,
                ));
            }
        }
        Ok(())
    }

    fn verify_with_sidecar_handle(&self, connection: &Connection) -> SqliteResult<()> {
        self.verify(connection)?;
        if self.owner_private && (self.wal.is_some() || self.shm.is_some()) {
            #[cfg(unix)]
            {
                match runne_sqlite_handle_identity::journal_file_has_moved(connection) {
                    Ok(Some(false)) => {}
                    Ok(Some(true)) | Ok(None) | Err(_) => {
                        return Err(diagnostic_error(
                            SchemaOpenDiagnostic::FileIdentityUncertain,
                        ));
                    }
                }
            }
            #[cfg(windows)]
            {
                // The win32 VFS has no HAS_MOVED; compare the journal handle
                // SQLite actually holds against the retained WAL anchor. A
                // missing anchor or a missing journal is uncertain, not moved.
                let anchor = self.wal.as_ref().map(|wal| &wal.identity);
                let journal = runne_sqlite_native_identity::opened_journal_identity(connection);
                match (journal, anchor) {
                    (Ok(Some(actual)), Some(expected))
                        if FileIdentity(actual) == *expected => {}
                    _ => {
                        return Err(diagnostic_error(
                            SchemaOpenDiagnostic::FileIdentityUncertain,
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn retain_created_sidecars(&mut self) -> SqliteResult<()> {
        if !self.owner_private {
            return Ok(());
        }
        validate_owner_private_recovery_files(&self.database.path).map_err(diagnostic_error)?;
        if self.wal.is_none() {
            self.wal = retain_optional(&sidecar_path(&self.database.path, "-wal"))
                .map_err(diagnostic_error)?;
        }
        if self.shm.is_none() {
            self.shm = retain_optional(&sidecar_path(&self.database.path, "-shm"))
                .map_err(diagnostic_error)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum IdentityHookStage {
    Retained,
    Opened,
    Classified,
}

#[cfg(any(unix, windows))]
fn retain_optional(path: &Path) -> Result<Option<RetainedFileIdentity>, SchemaOpenDiagnostic> {
    match fs::symlink_metadata(path) {
        Ok(_) => match RetainedFileIdentity::open(path) {
            Ok(identity) => Ok(Some(identity)),
            Err(SchemaOpenDiagnostic::FileIdentityUncertain) if !path.exists() => Ok(None),
            Err(error) => Err(error),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SchemaOpenDiagnostic::FileIdentityUncertain),
    }
}

#[cfg(any(unix, windows))]
fn optional_retained_unchanged(
    retained: &Option<RetainedFileIdentity>,
    path: &Path,
) -> SqliteResult<bool> {
    match retained {
        Some(retained) => retained.unchanged().map_err(diagnostic_error),
        None => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            _ => Ok(false),
        },
    }
}

#[cfg(unix)]
fn sqlite_main_matches_expected(
    connection: &Connection,
    _expected: &FileIdentity,
) -> bool {
    sqlite_main_has_moved(connection).map(|moved| !moved).unwrap_or(false)
}

/// The win32 VFS answers `SQLITE_NOTFOUND` to `SQLITE_FCNTL_HAS_MOVED`, so the
/// movement check compares the exact handle SQLite holds open against the
/// guard's retained anchor instead of a second path lookup.
#[cfg(windows)]
fn sqlite_main_matches_expected(
    connection: &Connection,
    expected: &FileIdentity,
) -> bool {
    runne_sqlite_native_identity::opened_database_identity(connection)
        .map(|actual| FileIdentity(actual) == *expected)
        .unwrap_or(false)
}

#[cfg(unix)]
fn sqlite_main_has_moved(connection: &Connection) -> SqliteResult<bool> {
    runne_sqlite_handle_identity::main_file_has_moved(connection).map_err(|_| {
        diagnostic_error(SchemaOpenDiagnostic::FileIdentityUncertain)
    })
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

fn path_is_safe(path: &Path) -> bool {
    !path.to_string_lossy().contains(['?', '#', '%'])
}
