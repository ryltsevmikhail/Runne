//! File-system primitives for the fixture promotion-store adapter.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::AuthorityError;

pub fn temp_file(path: &Path, bytes: &[u8]) -> Result<PathBuf, AuthorityError> {
    let parent = path
        .parent()
        .ok_or(AuthorityError::DurableStateUnavailable)?;
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or(AuthorityError::DurableStateUnavailable)?;
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .map_err(|_| AuthorityError::DurableStateUnavailable)?
        .read_exact(&mut random)
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    let temp = parent.join(format!(
        ".{name}.{}.tmp",
        crate::threshold_fixture_wire::hex(&random)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(&temp)
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|_| AuthorityError::DurableStateUnavailable)?;
    Ok(temp)
}

pub fn safe_file(path: &Path) -> Result<(), AuthorityError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AuthorityError::DurableStateUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(AuthorityError::DurableStateUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AuthorityError::DurableStateUnavailable);
        }
    }
    #[cfg(not(unix))]
    {
        return Err(AuthorityError::DurableStateUnavailable);
    }
    Ok(())
}

pub fn sync_parent(path: &Path) -> Result<(), AuthorityError> {
    File::open(
        path.parent()
            .ok_or(AuthorityError::DurableStateUnavailable)?,
    )
    .and_then(|file| file.sync_all())
    .map_err(|_| AuthorityError::DurableStateUnavailable)
}
