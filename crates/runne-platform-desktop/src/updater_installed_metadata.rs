//! Durable, native-owned signed update metadata for installed tuple admission.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{UpdateMetadataV2, VerifiedUpdateV2};

const MAX_METADATA_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum InstalledUpdateMetadataError {
    #[error("installed update metadata is corrupt")]
    Corrupt,
    #[error("installed update metadata operation failed")]
    Io,
}

/// Stores exactly one complete, threshold-signed metadata envelope per update.
#[derive(Clone, Debug)]
pub struct InstalledUpdateMetadataJournal {
    path: PathBuf,
}

impl InstalledUpdateMetadataJournal {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn persist(
        &self,
        update: &VerifiedUpdateV2,
    ) -> Result<String, InstalledUpdateMetadataError> {
        let bytes = serde_json::to_vec(update.metadata())
            .map_err(|_| InstalledUpdateMetadataError::Corrupt)?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(InstalledUpdateMetadataError::Corrupt);
        }
        let binding = hex::encode(Sha256::digest(&bytes));
        let parent = self.path.parent().ok_or(InstalledUpdateMetadataError::Io)?;
        fs::create_dir_all(parent).map_err(|_| InstalledUpdateMetadataError::Io)?;
        let sequence = self.next_sequence()?;
        let temporary = numbered_path(&self.path, sequence, "tmp");
        let final_path = numbered_path(&self.path, sequence, "json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| InstalledUpdateMetadataError::Io)?;
        file.write_all(&bytes)
            .map_err(|_| InstalledUpdateMetadataError::Io)?;
        file.sync_all()
            .map_err(|_| InstalledUpdateMetadataError::Io)?;
        drop(file);
        publish_no_replace(&temporary, &final_path)?;
        sync_parent(parent)?;
        for path in self.candidate_paths()? {
            if path != final_path {
                let _ = fs::remove_file(path);
            }
        }
        Ok(binding)
    }

    pub fn read(&self) -> Result<Option<(UpdateMetadataV2, String)>, InstalledUpdateMetadataError> {
        let Some(path) = self.latest_path()? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        open_regular_file(&path)?
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| InstalledUpdateMetadataError::Io)?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(InstalledUpdateMetadataError::Corrupt);
        }
        serde_json::from_slice(&bytes)
            .map(|metadata| Some((metadata, hex::encode(Sha256::digest(&bytes)))))
            .map_err(|_| InstalledUpdateMetadataError::Corrupt)
    }

    fn latest_path(&self) -> Result<Option<PathBuf>, InstalledUpdateMetadataError> {
        let mut paths = self.candidate_paths()?;
        paths.sort_by_key(|path| sequence_of(path));
        Ok(paths.pop())
    }

    fn next_sequence(&self) -> Result<u64, InstalledUpdateMetadataError> {
        Ok(self
            .latest_path()?
            .as_deref()
            .and_then(sequence_of)
            .unwrap_or(0)
            + 1)
    }

    fn candidate_paths(&self) -> Result<Vec<PathBuf>, InstalledUpdateMetadataError> {
        let parent = self.path.parent().ok_or(InstalledUpdateMetadataError::Io)?;
        let base = self
            .path
            .file_name()
            .ok_or(InstalledUpdateMetadataError::Io)?
            .to_string_lossy();
        let entries = match fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(InstalledUpdateMetadataError::Io),
        };
        Ok(entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .starts_with(&format!("{base}."))
                    && sequence_of(path).is_some()
            })
            .collect())
    }
}

fn numbered_path(base: &Path, sequence: u64, suffix: &str) -> PathBuf {
    let mut path = base.as_os_str().to_os_string();
    path.push(format!(".{sequence}.{suffix}"));
    PathBuf::from(path)
}

fn sequence_of(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_string_lossy();
    let (prefix, suffix) = name.rsplit_once('.')?;
    (suffix == "json").then_some(())?;
    prefix.rsplit_once('.')?.1.parse().ok()
}

fn open_regular_file(path: &Path) -> Result<File, InstalledUpdateMetadataError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(path)
    };
    #[cfg(not(any(unix, windows)))]
    let file = OpenOptions::new().read(true).open(path);
    let file = file.map_err(|_| InstalledUpdateMetadataError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| InstalledUpdateMetadataError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_METADATA_BYTES {
        return Err(InstalledUpdateMetadataError::Corrupt);
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(&metadata) != 1 {
        return Err(InstalledUpdateMetadataError::Corrupt);
    }
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(&metadata) & 0x400 != 0 {
        return Err(InstalledUpdateMetadataError::Corrupt);
    }
    Ok(file)
}

fn publish_no_replace(
    temporary: &Path,
    final_path: &Path,
) -> Result<(), InstalledUpdateMetadataError> {
    #[cfg(windows)]
    {
        let source = runne_windows_native_handle::inspect_regular_file(temporary)
            .map_err(|_| InstalledUpdateMetadataError::Io)?;
        runne_windows_native_handle::move_regular_file_no_replace_write_through(
            temporary,
            final_path,
            source.id(),
        )
        .map_err(|_| InstalledUpdateMetadataError::Io)
    }
    #[cfg(not(windows))]
    {
        fs::rename(temporary, final_path).map_err(|_| InstalledUpdateMetadataError::Io)
    }
}

fn sync_parent(parent: &Path) -> Result<(), InstalledUpdateMetadataError> {
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstalledUpdateMetadataError::Io)?;
    #[cfg(windows)]
    let _ = parent;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_partial_temp_cannot_replace_the_last_published_record() {
        let directory = tempfile::tempdir().unwrap();
        let journal = InstalledUpdateMetadataJournal::new(directory.path().join("metadata"));
        let final_path = numbered_path(&journal.path, 1, "json");
        std::fs::write(&final_path, b"final").unwrap();
        std::fs::write(numbered_path(&journal.path, 2, "tmp"), b"partial").unwrap();
        assert_eq!(journal.latest_path().unwrap(), Some(final_path));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_fifo_metadata_inputs_fail_closed_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink("missing", &link).unwrap();
        assert!(open_regular_file(&link).is_err());
        let fifo = directory.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(open_regular_file(&fifo).is_err());
    }
}
