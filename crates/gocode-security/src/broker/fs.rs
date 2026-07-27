use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::fd::OwnedFd;

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

#[derive(Debug)]
pub struct FsHandle {
    pub root_id: String,
    pub path: PathBuf,
    #[cfg(unix)]
    fd: Option<OwnedFd>,
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
        #[cfg(unix)]
        let (canonical, fd) = if workspace_root.policy.symlink_policy != SymlinkPolicy::Follow {
            let resolution = super::fs_unix::resolve_nofollow(
                &workspace_root.canonical_path,
                &relative.components,
                rustix::fs::OFlags::RDONLY,
            )?;
            (resolution.path, resolution.file_fd)
        } else {
            let canonical = fs::canonicalize(&full_path)
                .map_err(|error| FsBrokerError::Io(error.to_string()))?;
            let fd = super::fs_unix::open_follow(&canonical, rustix::fs::OFlags::RDONLY)?;
            (canonical, fd)
        };
        #[cfg(not(unix))]
        let canonical = {
            if workspace_root.policy.symlink_policy != SymlinkPolicy::Follow {
                let mut current = workspace_root.canonical_path.clone();
                for component in &relative.components {
                    current.push(component);
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                    if metadata.file_type().is_symlink() {
                        return Err(FsBrokerError::SymlinkEscapesRoot);
                    }
                }
            }
            fs::canonicalize(&full_path).map_err(|error| FsBrokerError::Io(error.to_string()))?
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
            path: canonical,
            #[cfg(unix)]
            fd: Some(fd),
        })
    }

    pub fn resolve_and_identity(
        &self,
        root: &RootHandle,
        path: &CanonicalPath,
    ) -> Result<(FsHandle, FsIdentity), FsBrokerError> {
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
            let _metadata =
                fs::metadata(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))?;
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
        let workspace_root = self.find_root(&root.root_id)?;
        if !workspace_root.policy.write_allowed {
            return Err(FsBrokerError::PermissionDenied);
        }
        #[cfg(unix)]
        let handle = self.resolve_for_write(root, path)?;
        #[cfg(not(unix))]
        let handle = self.resolve(root, path)?;
        #[cfg(unix)]
        let mut file = file_from_held_fd(&handle)?;
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .open(&handle.path)
            .map_err(|error| FsBrokerError::Io(error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| FsBrokerError::Io(error.to_string()))?;
        #[cfg(unix)]
        let current_identity = {
            use std::os::unix::fs::MetadataExt;
            FsIdentity {
                inode: metadata.ino(),
                device: metadata.dev(),
            }
        };
        #[cfg(not(unix))]
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

    pub fn write_created(
        &self,
        handle: &CreatedFsHandle,
        data: &[u8],
    ) -> Result<(), FsBrokerError> {
        let workspace_root = self.find_root(&handle.root_id)?;
        if !workspace_root.policy.write_allowed {
            return Err(FsBrokerError::PermissionDenied);
        }
        fs::write(&handle.path, data).map_err(|error| FsBrokerError::Io(error.to_string()))
    }

    pub fn read(&self, handle: &FsHandle) -> Result<Vec<u8>, FsBrokerError> {
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
        #[cfg(not(unix))]
        {
            fs::read(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))
        }
    }

    pub fn list(&self, handle: &FsHandle) -> Result<Vec<String>, FsBrokerError> {
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
        #[cfg(not(unix))]
        {
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
    }

    pub fn create(
        &self,
        root: &RootHandle,
        relative: &CanonicalPath,
    ) -> Result<CreatedFsHandle, FsBrokerError> {
        let workspace_root = self.find_root(&root.root_id)?;
        if !workspace_root.policy.create_allowed {
            return Err(FsBrokerError::PermissionDenied);
        }
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
        let workspace_root = self.find_root(&handle.root_id)?;
        if !workspace_root.policy.delete_allowed {
            return Err(FsBrokerError::PermissionDenied);
        }
        fs::remove_file(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))
    }

    fn find_root(&self, root_id: &str) -> Result<&WorkspaceRoot, FsBrokerError> {
        self.roots
            .iter()
            .find(|root| root.root_id == root_id)
            .ok_or(FsBrokerError::RootNotFound)
    }

    #[cfg(unix)]
    fn resolve_for_write(
        &self,
        root: &RootHandle,
        relative: &CanonicalPath,
    ) -> Result<FsHandle, FsBrokerError> {
        let workspace_root = self.find_root(&root.root_id)?;
        let full_path = workspace_root
            .canonical_path
            .join(relative.components.join("/"));
        let (canonical, fd) = if workspace_root.policy.symlink_policy != SymlinkPolicy::Follow {
            let resolution = super::fs_unix::resolve_nofollow(
                &workspace_root.canonical_path,
                &relative.components,
                rustix::fs::OFlags::RDWR,
            )?;
            (resolution.path, resolution.file_fd)
        } else {
            let canonical = fs::canonicalize(&full_path)
                .map_err(|error| FsBrokerError::Io(error.to_string()))?;
            let fd = super::fs_unix::open_follow(&canonical, rustix::fs::OFlags::RDWR)?;
            (canonical, fd)
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
            path: canonical,
            fd: Some(fd),
        })
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
    fn write_revalidates_and_mutates_the_opened_file() {
        let broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let path = CanonicalPath::new("file.txt").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("file.txt"), b"original").unwrap();
        let (_, identity) = broker.resolve_and_identity(&root, &path).unwrap();

        broker
            .write_with_revalidation(&root, &path, b"replacement", &identity)
            .unwrap();

        assert_eq!(
            fs::read(workspace_root.canonical_path.join("file.txt")).unwrap(),
            b"replacement"
        );
    }

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
    fn create_rejected_when_policy_create_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        broker.roots[0].policy.create_allowed = false;

        let result = broker.create(&root, &CanonicalPath::new("new.txt").unwrap());

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[test]
    fn delete_rejected_when_policy_delete_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let workspace_root = broker.find_root("ws1").unwrap();
        fs::write(workspace_root.canonical_path.join("test.txt"), b"hello").unwrap();
        let handle = broker
            .resolve(&root, &CanonicalPath::new("test.txt").unwrap())
            .unwrap();
        broker.roots[0].policy.delete_allowed = false;

        let result = broker.delete(&handle);

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
    }

    #[test]
    fn write_created_rejected_when_policy_write_allowed_false() {
        let mut broker = test_broker();
        let root = broker.open_root("ws1").unwrap();
        let created = broker
            .create(&root, &CanonicalPath::new("new.txt").unwrap())
            .unwrap();
        broker.roots[0].policy.write_allowed = false;

        let result = broker.write_created(&created, b"hello");

        assert!(matches!(result, Err(FsBrokerError::PermissionDenied)));
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
}
