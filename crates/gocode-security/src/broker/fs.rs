#[cfg(not(target_os = "windows"))]
use std::fs;
#[cfg(all(test, target_os = "windows"))]
use std::fs;
#[cfg(not(target_os = "windows"))]
use std::io::Read;
#[cfg(all(not(unix), not(target_os = "windows")))]
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
#[cfg(not(target_os = "windows"))]
use std::sync::Arc;

#[cfg(all(not(unix), not(target_os = "windows")))]
use std::fs::OpenOptions;
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
#[derive(Debug, Clone)]
pub struct RootHandle {
    root_id: String,
    binding: BrokerBinding,
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
#[derive(Debug, Clone)]
pub struct CreatedFsHandle {
    #[cfg(all(not(unix), not(target_os = "windows")))]
    root_id: String,
    binding: BrokerBinding,
    #[cfg(all(not(unix), not(target_os = "windows")))]
    path: PathBuf,
}

/// Opaque Windows marker: the backend always fails closed before using a handle.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
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
    pub fn new(roots: Vec<WorkspaceRoot>) -> Self {
        #[cfg(not(target_os = "windows"))]
        {
            Self {
                roots,
                binding: BrokerBinding::new(),
            }
        }
        #[cfg(all(target_os = "windows", test))]
        {
            Self { roots }
        }
        #[cfg(all(target_os = "windows", not(test)))]
        {
            let _ = roots;
            Self {}
        }
    }

    pub fn open_root(&self, root_id: &str) -> Result<RootHandle, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root_id);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        if self.roots.iter().any(|root| root.root_id == root_id) {
            Ok(RootHandle {
                root_id: root_id.to_string(),
                binding: self.binding.clone(),
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
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, relative);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_root_handle(root)?;
            let workspace_root = self.find_root_for_root_handle(root)?;
            #[cfg(unix)]
            let (canonical, fd) = {
                let resolution = super::fs_unix::resolve_nofollow(
                    &workspace_root.canonical_path,
                    &relative.components,
                    rustix::fs::OFlags::RDONLY,
                )?;
                (resolution.path, resolution.file_fd)
            };
            #[cfg(all(not(unix), not(target_os = "windows")))]
            let canonical = {
                let mut current = workspace_root.canonical_path.clone();
                for component in &relative.components {
                    current.push(component);
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                    if metadata.file_type().is_symlink() {
                        return Err(FsBrokerError::SymlinkEscapesRoot);
                    }
                }
                let full_path = workspace_root
                    .canonical_path
                    .join(relative.components.join("/"));
                fs::canonicalize(&full_path)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?
            };
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
                binding: self.binding.clone(),
                #[cfg(not(unix))]
                path: canonical,
                #[cfg(unix)]
                fd: Some(fd),
            })
        }
    }

    pub fn resolve_and_identity(
        &self,
        root: &RootHandle,
        path: &CanonicalPath,
    ) -> Result<(FsHandle, FsIdentity), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, path);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let handle = self.resolve(root, path)?;
            #[cfg(unix)]
            {
                let stat = rustix::fs::fstat(handle_fd(&handle)?)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                Ok((
                    handle,
                    FsIdentity {
                        inode: stat.st_ino,
                        device: u64::try_from(stat.st_dev)
                            .map_err(|_| FsBrokerError::Io("negative device identity".into()))?,
                    },
                ))
            }
            #[cfg(not(unix))]
            {
                let _metadata = fs::metadata(&handle.path)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                Ok((
                    handle,
                    FsIdentity {
                        inode: 0,
                        device: 0,
                    },
                ))
            }
        }
    }

    pub fn write_with_revalidation(
        &self,
        root: &RootHandle,
        path: &CanonicalPath,
        data: &[u8],
        expected_identity: &FsIdentity,
    ) -> Result<(), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, path, data, expected_identity);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(unix)]
        {
            let _ = (self, root, path, data, expected_identity);
            Err(FsBrokerError::MutationUnavailable)
        }
        #[cfg(all(not(unix), not(target_os = "windows")))]
        {
            self.validate_root_handle(root)?;
            let workspace_root = self.find_root_for_root_handle(root)?;
            if !workspace_root.policy.write_allowed {
                return Err(FsBrokerError::PermissionDenied);
            }
            let handle = self.resolve(root, path)?;
            let mut file = OpenOptions::new()
                .write(true)
                .open(&handle.path)
                .map_err(|error| FsBrokerError::Io(error.to_string()))?;
            let metadata = file
                .metadata()
                .map_err(|error| FsBrokerError::Io(error.to_string()))?;
            let current_identity = FsIdentity {
                inode: 0,
                device: 0,
            };
            if current_identity != *expected_identity {
                return Err(FsBrokerError::IdentityMismatch);
            }
            file.set_len(0)
                .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
                .and_then(|()| file.write_all(data))
                .and_then(|()| file.flush())
                .map_err(|error| FsBrokerError::Io(error.to_string()))
        }
    }

    pub fn write_created(
        &self,
        handle: &CreatedFsHandle,
        data: &[u8],
    ) -> Result<(), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle, data);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_created_handle(handle)?;
            #[cfg(unix)]
            {
                let _ = (handle, data);
                Err(FsBrokerError::MutationUnavailable)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let workspace_root = self.find_root(&handle.root_id)?;
                if !workspace_root.policy.write_allowed {
                    return Err(FsBrokerError::PermissionDenied);
                }
                fs::write(&handle.path, data).map_err(|error| FsBrokerError::Io(error.to_string()))
            }
        }
    }

    pub fn read(&self, handle: &FsHandle) -> Result<Vec<u8>, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_fs_handle(handle)?;
            let workspace_root = self.find_root(&handle.root_id)?;
            if !workspace_root.policy.read_allowed {
                return Err(FsBrokerError::PermissionDenied);
            }
            #[cfg(unix)]
            {
                let mut file = file_from_held_fd(handle)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                Ok(contents)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                fs::read(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))
            }
        }
    }

    pub fn list(&self, handle: &FsHandle) -> Result<Vec<String>, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_fs_handle(handle)?;
            let workspace_root = self.find_root(&handle.root_id)?;
            if !workspace_root.policy.read_allowed {
                return Err(FsBrokerError::PermissionDenied);
            }
            #[cfg(unix)]
            {
                rustix::fs::Dir::read_from(handle_fd(handle)?)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?
                    .filter_map(|entry| match entry {
                        Ok(entry) => {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            (!matches!(name.as_str(), "." | "..")).then_some(Ok(name))
                        }
                        Err(error) => Some(Err(FsBrokerError::Io(error.to_string()))),
                    })
                    .collect()
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let entries = fs::read_dir(&handle.path)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                entries
                    .map(|entry| {
                        entry
                            .map(|entry| entry.file_name().to_string_lossy().to_string())
                            .map_err(|error| FsBrokerError::Io(error.to_string()))
                    })
                    .collect()
            }
        }
    }

    pub fn create(
        &self,
        root: &RootHandle,
        relative: &CanonicalPath,
    ) -> Result<CreatedFsHandle, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, relative);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_root_handle(root)?;
            #[cfg(unix)]
            {
                let _ = (root, relative);
                Err(FsBrokerError::MutationUnavailable)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let workspace_root = self.find_root(&root.root_id)?;
                if !workspace_root.policy.create_allowed {
                    return Err(FsBrokerError::PermissionDenied);
                }
                let full_path = workspace_root
                    .canonical_path
                    .join(relative.components.join("/"));
                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                }
                fs::write(&full_path, b"").map_err(|error| FsBrokerError::Io(error.to_string()))?;
                let canonical = fs::canonicalize(&full_path)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                Ok(CreatedFsHandle {
                    root_id: root.root_id.clone(),
                    binding: self.binding.clone(),
                    path: canonical,
                })
            }
        }
    }

    pub fn delete(&self, handle: &FsHandle) -> Result<(), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle);
            return Err(FsBrokerError::BackendUnavailable);
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_fs_handle(handle)?;
            #[cfg(unix)]
            {
                let _ = handle;
                Err(FsBrokerError::MutationUnavailable)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let workspace_root = self.find_root(&handle.root_id)?;
                if !workspace_root.policy.delete_allowed {
                    return Err(FsBrokerError::PermissionDenied);
                }
                fs::remove_file(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))
            }
        }
    }

    #[cfg(any(not(target_os = "windows"), test))]
    fn find_root(&self, root_id: &str) -> Result<&WorkspaceRoot, FsBrokerError> {
        self.roots
            .iter()
            .find(|root| root.root_id == root_id)
            .ok_or(FsBrokerError::RootNotFound)
    }

    #[cfg(not(target_os = "windows"))]
    fn find_root_for_root_handle(
        &self,
        root: &RootHandle,
    ) -> Result<&WorkspaceRoot, FsBrokerError> {
        self.validate_root_handle(root)?;
        self.find_root(&root.root_id)
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_root_handle(&self, handle: &RootHandle) -> Result<(), FsBrokerError> {
        self.binding
            .matches(&handle.binding)
            .then_some(())
            .ok_or(FsBrokerError::PermissionDenied)
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_fs_handle(&self, handle: &FsHandle) -> Result<(), FsBrokerError> {
        self.binding
            .matches(&handle.binding)
            .then_some(())
            .ok_or(FsBrokerError::PermissionDenied)
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_created_handle(&self, handle: &CreatedFsHandle) -> Result<(), FsBrokerError> {
        self.binding
            .matches(&handle.binding)
            .then_some(())
            .ok_or(FsBrokerError::PermissionDenied)
    }
}

#[cfg(unix)]
fn handle_fd(handle: &FsHandle) -> Result<&OwnedFd, FsBrokerError> {
    handle
        .fd
        .as_ref()
        .ok_or_else(|| FsBrokerError::Io("missing file descriptor".into()))
}

#[cfg(unix)]
fn file_from_held_fd(handle: &FsHandle) -> Result<fs::File, FsBrokerError> {
    let fd = handle_fd(handle)?;
    // Дескриптор дублируется с CLOEXEC, сохраняя исходный descriptor у handle.
    let duplicate = rustix::io::fcntl_dupfd_cloexec(fd, 0)
        .map_err(|error| FsBrokerError::Io(error.to_string()))?;
    Ok(fs::File::from(duplicate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_broker() -> FilesystemBroker {
        let temporary_root = std::env::temp_dir().join(format!(
            "gocode_fs_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
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

    #[cfg(not(target_os = "windows"))]
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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn read_rejected_when_policy_read_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("test.txt"), b"hello").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
            .unwrap();
        broker.roots[0].policy.read_allowed = false;

        let result = broker.read(&handle);

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn handles_are_rejected_by_a_different_broker_with_the_same_root_id() {
        let temporary_root_a = std::env::temp_dir().join(format!(
            "gocode_fs_cross_broker_a_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let temporary_root_b = std::env::temp_dir().join(format!(
            "gocode_fs_cross_broker_b_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&temporary_root_a);
        let _ = fs::remove_dir_all(&temporary_root_b);
        fs::create_dir_all(temporary_root_a.join("directory")).unwrap();
        fs::create_dir_all(&temporary_root_b).unwrap();
        fs::write(temporary_root_a.join("secret.txt"), b"secret").unwrap();
        fs::write(temporary_root_a.join("directory/entry.txt"), b"entry").unwrap();

        let policy = WorkspacePolicy {
            read_allowed: true,
            write_allowed: true,
            create_allowed: true,
            delete_allowed: true,
            symlink_policy: SymlinkPolicy::NoFollow,
        };
        let broker_a = FilesystemBroker::new(vec![WorkspaceRoot {
            root_id: "shared".into(),
            canonical_path: fs::canonicalize(&temporary_root_a).unwrap(),
            policy: policy.clone(),
        }]);
        let broker_b = FilesystemBroker::new(vec![WorkspaceRoot {
            root_id: "shared".into(),
            canonical_path: fs::canonicalize(&temporary_root_b).unwrap(),
            policy,
        }]);
        let root_a = broker_a.open_root("shared").unwrap();
        let file_handle = broker_a
            .resolve(&root_a, &CanonicalPath::new("secret.txt").unwrap())
            .unwrap();
        let directory_handle = broker_a
            .resolve(&root_a, &CanonicalPath::new("directory").unwrap())
            .unwrap();

        assert!(matches!(
            broker_b.read(&file_handle),
            Err(FsBrokerError::PermissionDenied)
        ));
        assert!(matches!(
            broker_b.list(&directory_handle),
            Err(FsBrokerError::PermissionDenied)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn resolved_handle_reads_the_held_file_descriptor() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        let path = workspace_root.canonical_path.join("test.txt");
        fs::write(&path, b"original").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
            .unwrap();
        let replacement = workspace_root.canonical_path.join("test.txt.replacement");
        fs::write(&replacement, b"replacement").unwrap();
        fs::rename(replacement, path).unwrap();

        assert_eq!(broker.read(&handle).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn write_is_unavailable_before_identity_revalidation() {
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
        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("file.txt")).unwrap(),
            b"new content"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_is_unavailable_without_changing_file_bytes() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let path = CanonicalPath::new("file.txt").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
        let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();

        let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("file.txt")).unwrap(),
            b"original"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_is_unavailable_when_policy_write_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let path = CanonicalPath::new("file.txt").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
        let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();
        broker.roots[0].policy.write_allowed = false;

        let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    }

    #[cfg(all(not(unix), not(target_os = "windows")))]
    #[test]
    fn write_rejected_when_policy_write_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let path = CanonicalPath::new("file.txt").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
        let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();
        broker.roots[0].policy.write_allowed = false;

        let result = broker.write_with_revalidation(&root, &path, b"replacement", &identity);

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[cfg(unix)]
    #[test]
    fn create_is_unavailable_without_creating_files_or_directories() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(
            workspace_root.canonical_path.join("existing.txt"),
            b"original",
        )
        .unwrap();
        let entries_before = directory_entry_names(&workspace_root.canonical_path);

        let result = broker.create(&root, &CanonicalPath::new("new/nested.txt").unwrap());

        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("existing.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            directory_entry_names(&workspace_root.canonical_path),
            entries_before
        );
        assert!(!workspace_root.canonical_path.join("new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_created_is_unavailable_without_changing_file_bytes() {
        let broker = test_broker();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(
            workspace_root.canonical_path.join("existing.txt"),
            b"original",
        )
        .unwrap();
        let entries_before = directory_entry_names(&workspace_root.canonical_path);
        let created = CreatedFsHandle {
            binding: broker.binding.clone(),
        };

        let result = broker.write_created(&created, b"replacement");

        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("existing.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            directory_entry_names(&workspace_root.canonical_path),
            entries_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn delete_is_unavailable_without_removing_file_or_directory_entries() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("test.txt"), b"hello").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
            .unwrap();
        let entries_before = directory_entry_names(&workspace_root.canonical_path);

        let result = broker.delete(&handle);

        assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("test.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            directory_entry_names(&workspace_root.canonical_path),
            entries_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn list_rejected_when_policy_read_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::create_dir_all(workspace_root.canonical_path.join("directory")).unwrap();
        fs::write(
            workspace_root.canonical_path.join("directory/entry.txt"),
            b"data",
        )
        .unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("directory").unwrap())
            .unwrap();
        broker.roots[0].policy.read_allowed = false;

        let result = broker.list(&handle);

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[cfg(all(not(unix), not(target_os = "windows")))]
    #[test]
    fn fallback_list_rejected_when_policy_read_allowed_false_without_entry_disclosure() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::create_dir_all(workspace_root.canonical_path.join("directory")).unwrap();
        fs::write(
            workspace_root
                .canonical_path
                .join("directory/secret-entry.txt"),
            b"data",
        )
        .unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("directory").unwrap())
            .unwrap();
        broker.roots[0].policy.read_allowed = false;

        let result = broker.list(&handle);

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[cfg(unix)]
    fn directory_entry_names(directory: &std::path::Path) -> Vec<String> {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[cfg(not(target_os = "windows"))]
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

    #[cfg(unix)]
    #[test]
    fn no_follow_policy_rejects_a_symlink_even_when_target_is_inside_root() {
        use std::os::unix::fs::symlink;

        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("target.txt"), b"data").unwrap();
        symlink(
            workspace_root.canonical_path.join("target.txt"),
            workspace_root.canonical_path.join("link.txt"),
        )
        .unwrap();

        let result = broker.resolve(&root, &CanonicalPath::new("link.txt").unwrap());

        assert!(matches!(result, Err(FsBrokerError::SymlinkEscapesRoot)));
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_policy_rejects_a_symlink_in_an_intermediate_component() {
        use std::os::unix::fs::symlink;

        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::create_dir_all(workspace_root.canonical_path.join("real")).unwrap();
        fs::write(
            workspace_root.canonical_path.join("real/target.txt"),
            b"data",
        )
        .unwrap();
        symlink(
            workspace_root.canonical_path.join("real"),
            workspace_root.canonical_path.join("linked-dir"),
        )
        .unwrap();

        let result = broker.resolve(&root, &CanonicalPath::new("linked-dir/target.txt").unwrap());

        assert!(matches!(result, Err(FsBrokerError::NotDirectory)));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn protected_operations_are_unavailable_before_filesystem_effects() {
        let broker = test_broker();
        let workspace_root = broker.find_root("ws1").unwrap();
        let file_path = workspace_root.canonical_path.join("file.txt");
        let directory_path = workspace_root.canonical_path.join("directory");
        fs::write(&file_path, b"original").unwrap();
        fs::create_dir(&directory_path).unwrap();
        fs::write(directory_path.join("entry.txt"), b"entry").unwrap();
        let entries_before = directory_entry_names(&workspace_root.canonical_path);
        let root = RootHandle;
        let file_handle = FsHandle;
        let directory_handle = FsHandle;
        let created_handle = CreatedFsHandle;
        let path = CanonicalPath::new("file.txt").unwrap();

        assert!(matches!(
            broker.open_root("ws1"),
            Err(FsBrokerError::BackendUnavailable)
        ));

        assert!(matches!(
            broker.resolve(&root, &path),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.resolve_and_identity(&root, &path),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.read(&file_handle),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.list(&directory_handle),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.write_with_revalidation(
                &root,
                &path,
                b"replacement",
                &FsIdentity {
                    inode: 0,
                    device: 0,
                },
            ),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.create(&root, &CanonicalPath::new("new/nested.txt").unwrap()),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.write_created(&created_handle, b"replacement"),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert!(matches!(
            broker.delete(&file_handle),
            Err(FsBrokerError::BackendUnavailable)
        ));
        assert_eq!(
            fs::read(workspace_root.canonical_path.join("file.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            directory_entry_names(&workspace_root.canonical_path),
            entries_before
        );
        assert!(!workspace_root.canonical_path.join("new").exists());
        assert!(!workspace_root.canonical_path.join("created.txt").exists());
    }

    #[cfg(target_os = "windows")]
    fn directory_entry_names(directory: &std::path::Path) -> Vec<String> {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }
}
