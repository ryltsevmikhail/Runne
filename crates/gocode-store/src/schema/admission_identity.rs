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
        use std::os::unix::fs::MetadataExt;
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
fn admitted_files() -> &'static Mutex<Vec<FileIdentity>> {
    static FILES: OnceLock<Mutex<Vec<FileIdentity>>> = OnceLock::new();
    FILES.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(windows)]
fn admitted_paths() -> &'static Mutex<Vec<PathBuf>> {
    static PATHS: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    PATHS.get_or_init(|| Mutex::new(Vec::new()))
}

fn identity_is_admitted(path: &Path) -> Result<bool, SchemaOpenDiagnostic> {
    #[cfg(unix)]
    {
        let identity = file_identity(path)?;
        admitted_files()
            .lock()
            .map(|files| files.contains(&identity))
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
    }
    #[cfg(windows)]
    {
        admitted_paths()
            .lock()
            .map(|paths| {
                paths
                    .iter()
                    .any(|admitted| same_file::is_same_file(admitted, path).unwrap_or(false))
            })
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
    }
}

fn admit_identity(path: &Path) -> Result<(), SchemaOpenDiagnostic> {
    #[cfg(unix)]
    {
        let identity = file_identity(path)?;
        fs::canonicalize(path).map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        let mut files = admitted_files()
            .lock()
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        if !files.contains(&identity) {
            files.push(identity);
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        file_identity(path)?;
        let canonical =
            fs::canonicalize(path).map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        let mut paths = admitted_paths()
            .lock()
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        if !paths.iter().any(|admitted| admitted == &canonical) {
            paths.push(canonical);
        }
        Ok(())
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
