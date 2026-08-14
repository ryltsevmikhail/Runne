#[cfg(not(target_os = "windows"))]
use std::fs;
#[cfg(all(test, target_os = "windows"))]
use std::fs;
#[cfg(not(target_os = "windows"))]
use std::io::Read;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(target_os = "windows"))]
use std::sync::Arc;

#[cfg(unix)]
use std::os::fd::OwnedFd;

/// FilesystemBroker — единственный путь для filesystem access в protected контексте.
pub struct FilesystemBroker {
    #[cfg(not(target_os = "windows"))]
    roots: Vec<WorkspaceRoot>,
    #[cfg(not(target_os = "windows"))]
    binding: BrokerBinding,
    #[cfg(all(target_os = "windows", test))]
    roots: Vec<WorkspaceRoot>,
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone)]
struct BrokerBinding(Arc<()>);

#[cfg(not(target_os = "windows"))]
impl BrokerBinding {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

pub struct WorkspaceRoot {
    pub root_id: String,
    pub canonical_path: PathBuf,
    pub policy: WorkspacePolicy,
}

#[derive(Debug, Clone)]
pub struct WorkspacePolicy {
    pub read_allowed: bool,
    pub write_allowed: bool,
    pub create_allowed: bool,
    pub delete_allowed: bool,
    pub symlink_policy: SymlinkPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    NoFollow,
    Forbidden,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    components: Vec<String>,
}

impl CanonicalPath {
    pub fn new(path: &str) -> Result<Self, FsBrokerError> {
        if path.starts_with('/') || path.starts_with('\\') {
            return Err(FsBrokerError::PathNotRelative);
        }
        if path.contains("..") {
            return Err(FsBrokerError::PathEscapesRoot);
        }
        let components: Vec<String> = path
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .map(str::to_string)
            .collect();
        if components.is_empty() {
            return Err(FsBrokerError::PathNotRelative);
        }
        Ok(Self { components })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FsIdentity {
    pub inode: u64,
    pub device: u64,
}

/// ```compile_fail
/// use gocode_security::broker::fs::RootHandle;
///
/// let _ = RootHandle {
///     root_id: "workspace".into(),
/// };
/// ```
#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
pub struct RootHandle {
    root_id: String,
    binding: BrokerBinding,
    #[cfg(unix)]
    fd: Option<OwnedFd>,
    #[cfg(unix)]
    identity: FsIdentity,
}

/// Opaque Windows marker: the backend always fails closed before using a handle.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct RootHandle;

/// ```compile_fail
/// use gocode_security::broker::fs::FsHandle;
/// use std::path::PathBuf;
///
/// let _ = FsHandle {
///     root_id: "workspace".into(),
///     path: PathBuf::from("file.txt"),
/// };
/// ```
#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
pub struct FsHandle {
    root_id: String,
    binding: BrokerBinding,
    #[cfg(not(unix))]
    path: PathBuf,
    #[cfg(unix)]
    fd: Option<OwnedFd>,
}

/// Opaque Windows marker: the backend always fails closed before using a handle.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct FsHandle;

/// CreatedFsHandle — отдельный тип для freshly-created файлов.
/// Несовместим с FsHandle. Типовая система предотвращает bypass.
/// ```compile_fail
/// use gocode_security::broker::fs::CreatedFsHandle;
/// use std::path::PathBuf;
///
/// let _ = CreatedFsHandle {
///     root_id: "workspace".into(),
///     path: PathBuf::from("file.txt"),
/// };
/// ```
#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
pub struct CreatedFsHandle {
    #[cfg(not(target_os = "windows"))]
    root_id: String,
    binding: BrokerBinding,
    #[cfg(all(not(unix), not(target_os = "windows")))]
    path: PathBuf,
    #[cfg(unix)]
    fd: Option<OwnedFd>,
    #[cfg(unix)]
    parent_fd: Option<OwnedFd>,
    #[cfg(unix)]
    final_name: String,
}

/// Opaque Windows marker: the backend always fails closed before using a handle.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct CreatedFsHandle;

#[derive(Debug, Clone, thiserror::Error)]
pub enum FsBrokerError {
    #[error("filesystem broker backend unavailable")]
    BackendUnavailable,
    #[error("path is not relative")]
    PathNotRelative,
    #[error("path escapes root boundary")]
    PathEscapesRoot,
    #[error("symlink escapes root boundary")]
    SymlinkEscapesRoot,
    #[error("path component is not a directory")]
    NotDirectory,
    #[error("file identity mismatch — TOCTOU detected")]
    IdentityMismatch,
    #[error("sensitive path denied")]
    SensitivePathDenied,
    #[error("root not found")]
    RootNotFound,
    #[error("permission denied by workspace policy")]
    PermissionDenied,
    #[error("filesystem mutations are unavailable")]
    MutationUnavailable,
    #[error("file not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(String),
}

#[cfg(not(target_os = "windows"))]
const SENSITIVE_PATTERNS: &[&str] = &[
    ".git/",
    ".svn/",
    ".hg/",
    "*.pem",
    "*.key",
    ".env",
    "credentials",
    "secrets",
    "id_rsa",
    "id_ed25519",
];

impl FilesystemBroker {
    #[cfg(not(target_os = "windows"))]
    fn validate_sensitive_path(&self, path: &Path) -> Result<(), FsBrokerError> {
        let path_string = path.to_string_lossy();
        for pattern in SENSITIVE_PATTERNS {
            if pattern.contains('*') {
                let extension = pattern.trim_start_matches('*');
                if path_string.ends_with(extension) {
                    return Err(FsBrokerError::SensitivePathDenied);
                }
            } else if path_string.contains(pattern) {
                return Err(FsBrokerError::SensitivePathDenied);
            }
        }
        Ok(())
    }
}
