use std::fs;
use std::path::PathBuf;

/// FilesystemBroker — единственный путь для filesystem access в protected контексте.
pub struct FilesystemBroker {
    roots: Vec<WorkspaceRoot>,
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
    Follow,
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

#[derive(Debug, Clone)]
pub struct RootHandle {
    pub root_id: String,
}

#[derive(Debug, Clone)]
pub struct FsHandle {
    pub root_id: String,
    pub path: PathBuf,
}

/// CreatedFsHandle — отдельный тип для freshly-created файлов.
/// Несовместим с FsHandle. Типовая система предотвращает bypass.
#[derive(Debug, Clone)]
pub struct CreatedFsHandle {
    pub root_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum FsBrokerError {
    #[error("path is not relative")]
    PathNotRelative,
    #[error("path escapes root boundary")]
    PathEscapesRoot,
    #[error("symlink escapes root boundary")]
    SymlinkEscapesRoot,
    #[error("file identity mismatch — TOCTOU detected")]
    IdentityMismatch,
    #[error("sensitive path denied")]
    SensitivePathDenied,
    #[error("root not found")]
    RootNotFound,
    #[error("file not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(String),
}

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
    pub fn new(roots: Vec<WorkspaceRoot>) -> Self {
        Self { roots }
    }

    pub fn open_root(&self, root_id: &str) -> Result<RootHandle, FsBrokerError> {
        if self.roots.iter().any(|root| root.root_id == root_id) {
            Ok(RootHandle {
                root_id: root_id.to_string(),
            })
        } else {
            Err(FsBrokerError::RootNotFound)
        }
    }

    pub fn resolve(
        &self,
        root: &RootHandle,
        relative: &CanonicalPath,
    ) -> Result<FsHandle, FsBrokerError> {
        let workspace_root = self.find_root(&root.root_id)?;
        let full_path = workspace_root
            .canonical_path
            .join(relative.components.join("/"));
        let canonical =
            fs::canonicalize(&full_path).map_err(|error| FsBrokerError::Io(error.to_string()))?;
        if !canonical.starts_with(&workspace_root.canonical_path) {
            return Err(FsBrokerError::SymlinkEscapesRoot);
        }
        let path_string = canonical.to_string_lossy();
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
        Ok(FsHandle {
            root_id: root.root_id.clone(),
            path: canonical,
        })
    }

    pub fn resolve_and_identity(
        &self,
        root: &RootHandle,
        path: &CanonicalPath,
    ) -> Result<(FsHandle, FsIdentity), FsBrokerError> {
        let handle = self.resolve(root, path)?;
        let metadata =
            fs::metadata(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok((
                handle,
                FsIdentity {
                    inode: metadata.ino(),
                    device: metadata.dev(),
                },
            ))
        }
        #[cfg(not(unix))]
        {
            Ok((
                handle,
                FsIdentity {
                    inode: 0,
                    device: 0,
                },
            ))
        }
    }

    pub fn write_with_revalidation(
        &self,
        root: &RootHandle,
        path: &CanonicalPath,
        data: &[u8],
        expected_identity: &FsIdentity,
    ) -> Result<(), FsBrokerError> {
        let (handle, current_identity) = self.resolve_and_identity(root, path)?;
        if current_identity != *expected_identity {
            return Err(FsBrokerError::IdentityMismatch);
        }
        fs::write(&handle.path, data).map_err(|error| FsBrokerError::Io(error.to_string()))
    }

    pub fn write_created(
        &self,
        handle: &CreatedFsHandle,
        data: &[u8],
    ) -> Result<(), FsBrokerError> {
        fs::write(&handle.path, data).map_err(|error| FsBrokerError::Io(error.to_string()))
    }

    pub fn read(&self, handle: &FsHandle) -> Result<Vec<u8>, FsBrokerError> {
        fs::read(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))
    }

    pub fn list(&self, handle: &FsHandle) -> Result<Vec<String>, FsBrokerError> {
        let entries =
            fs::read_dir(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))?;
        entries
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().to_string())
                    .map_err(|error| FsBrokerError::Io(error.to_string()))
            })
            .collect()
    }

    pub fn create(
        &self,
        root: &RootHandle,
        relative: &CanonicalPath,
    ) -> Result<CreatedFsHandle, FsBrokerError> {
        let workspace_root = self.find_root(&root.root_id)?;
        let full_path = workspace_root
            .canonical_path
            .join(relative.components.join("/"));
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(|error| FsBrokerError::Io(error.to_string()))?;
        }
        fs::write(&full_path, b"").map_err(|error| FsBrokerError::Io(error.to_string()))?;
        let canonical =
            fs::canonicalize(&full_path).map_err(|error| FsBrokerError::Io(error.to_string()))?;
        Ok(CreatedFsHandle {
            root_id: root.root_id.clone(),
            path: canonical,
        })
    }

    pub fn delete(&self, handle: &FsHandle) -> Result<(), FsBrokerError> {
        fs::remove_file(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))
    }

    fn find_root(&self, root_id: &str) -> Result<&WorkspaceRoot, FsBrokerError> {
        self.roots
            .iter()
            .find(|root| root.root_id == root_id)
            .ok_or(FsBrokerError::RootNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_broker() -> FilesystemBroker {
        let temporary_root = std::env::temp_dir().join(format!(
            "gocode_fs_test_{}_{}",
            std::process::id(),
            format!("{:?}", std::thread::current().id())
        ));
        let _ = fs::remove_dir_all(&temporary_root);
        fs::create_dir_all(&temporary_root).unwrap();
        FilesystemBroker::new(vec![WorkspaceRoot {
            root_id: "ws1".into(),
            canonical_path: fs::canonicalize(temporary_root).unwrap(),
            policy: WorkspacePolicy {
                read_allowed: true,
                write_allowed: true,
                create_allowed: true,
                delete_allowed: true,
                symlink_policy: SymlinkPolicy::NoFollow,
            },
        }])
    }

    #[test]
    fn resolve_rejects_absolute_path() {
        assert!(CanonicalPath::new("/etc/passwd").is_err());
    }

    #[test]
    fn resolve_rejects_parent_directory_escape() {
        assert!(CanonicalPath::new("../escape").is_err());
    }

    #[test]
    fn resolve_and_read_valid_path() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("test.txt"), b"hello").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
            .unwrap();
        assert_eq!(broker.read(&handle).unwrap(), b"hello");
    }

    #[test]
    fn write_detects_toc_tou_race() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let path = CanonicalPath::new("file.txt").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
        let (_, identity_before) = broker.resolve_and_identity(&root, &path).unwrap();
        let temporary_path = workspace_root.canonical_path.join("file.txt.tmp");
        fs::write(&temporary_path, b"new content").unwrap();
        fs::rename(
            &temporary_path,
            workspace_root.canonical_path.join("file.txt"),
        )
        .unwrap();
        let result = broker.write_with_revalidation(&root, &path, b"data", &identity_before);
        assert!(matches!(result, Err(FsBrokerError::IdentityMismatch)));
    }

    #[test]
    fn create_returns_created_fs_handle() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let created = broker
            .create(&root, &CanonicalPath::new("new.txt").unwrap())
            .unwrap();
        broker.write_created(&created, b"hello").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("new.txt").unwrap())
            .unwrap();
        assert_eq!(broker.read(&handle).unwrap(), b"hello");
    }

    #[test]
    fn sensitive_path_denied() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::create_dir_all(workspace_root.canonical_path.join(".git")).unwrap();
        fs::write(workspace_root.canonical_path.join(".git/config"), b"data").unwrap();
        let result = broker.resolve(&root, &CanonicalPath::new(".git/config").unwrap());
        assert!(matches!(result, Err(FsBrokerError::SensitivePathDenied)));
    }
}
