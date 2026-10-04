//! Linux-only descriptor preparation for structured local commands.

use super::{RootHandleBrokerError, VerifiedRootHandle, platform};
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use std::fs::File;
use std::path::{Component, Path};

mod system;

/// Held workspace-root and cwd descriptors for one verified root.
pub struct LinuxCommandWorkspaceFiles {
    workspace: File,
    cwd: File,
}

/// Held workspace, cwd, and workspace-executable descriptors.
pub struct LinuxCommandFiles {
    workspace: LinuxCommandWorkspaceFiles,
    executable: File,
}

impl LinuxCommandWorkspaceFiles {
    /// Returns the held workspace root descriptor.
    #[must_use]
    pub const fn workspace(&self) -> &File {
        &self.workspace
    }

    /// Returns the opened working-directory descriptor.
    #[must_use]
    pub const fn cwd(&self) -> &File {
        &self.cwd
    }
}

impl LinuxCommandFiles {
    /// Returns the held workspace root descriptor.
    #[must_use]
    pub const fn workspace(&self) -> &File {
        self.workspace.workspace()
    }

    /// Returns the opened working-directory descriptor.
    #[must_use]
    pub const fn cwd(&self) -> &File {
        self.workspace.cwd()
    }

    /// Returns the opened workspace executable descriptor.
    #[must_use]
    pub const fn executable(&self) -> &File {
        &self.executable
    }
}

impl VerifiedRootHandle {
    /// Duplicates this root and opens a workspace-relative cwd; `.` names root.
    /// Use this for closed system-catalog executables which are opened separately.
    ///
    /// # Errors
    /// Returns a closed error for invalid cwd paths, traversal, links, mount
    /// crossing, wrong object kinds, or descriptor I/O failures.
    pub fn open_linux_command_workspace(
        &self,
        cwd: &Path,
    ) -> Result<LinuxCommandWorkspaceFiles, RootHandleBrokerError> {
        validate_relative(cwd, true)?;
        let workspace = self
            .handle
            .try_clone()
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        let cwd = if cwd == Path::new(".") {
            self.handle
                .try_clone()
                .map_err(|_| RootHandleBrokerError::Unavailable)?
        } else {
            open_beneath(&self.handle, cwd, true)?
        };
        Ok(LinuxCommandWorkspaceFiles { workspace, cwd })
    }

    /// Opens a workspace-relative executable and cwd without following links
    /// or crossing mounts. `cwd="."` names the verified root itself.
    ///
    /// # Errors
    /// Returns a closed error for invalid relative paths, traversal, links,
    /// mount crossing, wrong object kinds, or descriptor I/O failures.
    pub fn open_linux_command_files(
        &self,
        executable: &Path,
        cwd: &Path,
    ) -> Result<LinuxCommandFiles, RootHandleBrokerError> {
        validate_relative(executable, false)?;
        let workspace = self.open_linux_command_workspace(cwd)?;
        let executable = open_beneath(&self.handle, executable, false)?;
        let metadata =
            rustix::fs::fstat(&executable).map_err(|_| RootHandleBrokerError::Unavailable)?;
        if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file()
            || metadata.st_mode & 0o111 == 0
        {
            return Err(RootHandleBrokerError::Rejected);
        }
        Ok(LinuxCommandFiles {
            workspace,
            executable,
        })
    }
}

fn open_beneath(
    root: &platform::NativeDirectoryHandle,
    path: &Path,
    directory: bool,
) -> Result<File, RootHandleBrokerError> {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if directory {
        flags |= OFlags::DIRECTORY;
    } else {
        flags |= OFlags::NONBLOCK;
    }
    let descriptor = openat2(
        root,
        path,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| RootHandleBrokerError::Rejected)?;
    Ok(File::from(descriptor))
}

fn validate_relative(path: &Path, allow_dot: bool) -> Result<(), RootHandleBrokerError> {
    let value = path.to_str().ok_or(RootHandleBrokerError::Rejected)?;
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('/')
        || value.contains('\\')
        || value.as_bytes().contains(&0)
    {
        return Err(RootHandleBrokerError::Rejected);
    }
    if allow_dot && value == "." {
        return Ok(());
    }
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(RootHandleBrokerError::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "runne-linux-root-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn opens_dot_cwd_and_exact_executable_descriptor() {
        let temp = Temp::new();
        std::fs::create_dir(temp.0.join("bin")).unwrap();
        let executable = temp.0.join("bin/tool");
        std::fs::write(&executable, b"held-version").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = VerifiedRootHandle::open(&temp.0).unwrap();
        let opened = root
            .open_linux_command_files(Path::new("bin/tool"), Path::new("."))
            .unwrap();
        let root_fd = rustix::fs::fstat(root.handle.as_fd()).unwrap();
        let cwd_fd = rustix::fs::fstat(opened.cwd()).unwrap();
        assert_eq!(
            (root_fd.st_dev, root_fd.st_ino),
            (cwd_fd.st_dev, cwd_fd.st_ino)
        );
        std::fs::rename(&executable, temp.0.join("bin/old-tool")).unwrap();
        std::fs::write(&executable, b"replacement").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut held = opened.executable().try_clone().unwrap();
        let mut bytes = Vec::new();
        held.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"held-version");
    }

    #[test]
    fn rejects_symlinks_traversal_absolute_and_ambiguous_components() {
        let temp = Temp::new();
        std::fs::write(temp.0.join("tool"), b"x").unwrap();
        std::fs::set_permissions(temp.0.join("tool"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::os::unix::fs::symlink("tool", temp.0.join("link")).unwrap();
        let root = VerifiedRootHandle::open(&temp.0).unwrap();
        for path in ["../tool", "/tool", "./tool", "a//tool", "link"] {
            assert!(
                root.open_linux_command_files(Path::new(path), Path::new("."))
                    .is_err(),
                "{path}"
            );
        }
        assert!(
            root.open_linux_command_files(Path::new("tool"), Path::new("../"))
                .is_err()
        );
    }
}
