#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

pub fn tempdir() -> TempDir {
    let directory = tempfile::tempdir().expect("owner-private temporary directory");
    secure_directory(directory.path());
    directory
}

fn executable_tempdir() -> TempDir {
    #[cfg(unix)]
    let directory = std::env::var_os("XDG_RUNTIME_DIR")
        .and_then(|path| {
            tempfile::Builder::new()
                .prefix("runne-daemon-executable-")
                .tempdir_in(path)
                .ok()
        })
        .unwrap_or_else(|| {
            tempfile::Builder::new()
                .prefix("runne-daemon-executable-")
                .tempdir_in("/tmp")
                .expect("secure executable temporary directory")
        });
    #[cfg(not(unix))]
    let directory = tempfile::tempdir().expect("executable temporary directory");
    secure_directory(directory.path());
    directory
}

pub fn secure_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory");
    }
}

pub struct ControlledExecutable {
    _root: TempDir,
    path: PathBuf,
}

impl ControlledExecutable {
    pub fn copy_from(source: impl AsRef<Path>) -> Self {
        let root = executable_tempdir();
        let path = root.path().join("controlled-executable");
        fs::copy(source, &path).expect("copy controlled executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure controlled executable");
        }
        Self { _root: root, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
