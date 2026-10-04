use super::{LinuxCommandFiles, RootHandleBrokerError, VerifiedRootHandle};
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use std::fs::File;
use std::path::Path;

impl VerifiedRootHandle {
    /// Opens a closed catalog entry alongside a verified workspace and cwd.
    /// The caller supplies only an ID, never a filesystem path.
    ///
    /// # Errors
    /// Returns a closed error for an unknown catalog entry, unavailable or
    /// mutable system executable, or invalid workspace/cwd binding.
    pub fn open_linux_system_command_files(
        &self,
        catalog_id: &str,
        cwd: &Path,
    ) -> Result<LinuxCommandFiles, RootHandleBrokerError> {
        let path = match catalog_id {
            "shell" => Path::new("/usr/bin/bash"),
            _ => return Err(RootHandleBrokerError::Rejected),
        };
        let workspace = self.open_linux_command_workspace(cwd)?;
        let executable = open_system_executable(path)?;
        let metadata =
            rustix::fs::fstat(&executable).map_err(|_| RootHandleBrokerError::Unavailable)?;
        if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file()
            || metadata.st_mode & 0o111 == 0
            || metadata.st_uid != 0
            || metadata.st_mode & 0o022 != 0
        {
            return Err(RootHandleBrokerError::Rejected);
        }
        Ok(LinuxCommandFiles {
            workspace,
            executable,
        })
    }
}

fn open_system_executable(path: &Path) -> Result<File, RootHandleBrokerError> {
    let descriptor = openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RootHandleBrokerError::Unavailable)?;
    Ok(File::from(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "runne-linux-catalog-{}-{}",
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
    fn system_catalog_uses_held_executable_and_verified_workspace_cwd() {
        let temp = Temp::new();
        let root = VerifiedRootHandle::open(&temp.0).unwrap();
        let opened = root
            .open_linux_system_command_files("shell", Path::new("."))
            .unwrap();
        let metadata = rustix::fs::fstat(opened.executable()).unwrap();
        assert!(rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file());
        assert_eq!(metadata.st_uid, 0);
        let root_stat = rustix::fs::fstat(root.handle.as_fd()).unwrap();
        let workspace_stat = rustix::fs::fstat(opened.workspace()).unwrap();
        let cwd_stat = rustix::fs::fstat(opened.cwd()).unwrap();
        assert_eq!(
            (root_stat.st_dev, root_stat.st_ino),
            (workspace_stat.st_dev, workspace_stat.st_ino)
        );
        assert_eq!(
            (root_stat.st_dev, root_stat.st_ino),
            (cwd_stat.st_dev, cwd_stat.st_ino)
        );
        assert!(
            root.open_linux_system_command_files("/usr/bin/bash", Path::new("."))
                .is_err()
        );
    }
}
