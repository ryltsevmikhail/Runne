//! Durable, native-owned signed update metadata for installed tuple admission.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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

    pub fn persist(&self, update: &VerifiedUpdateV2) -> Result<(), InstalledUpdateMetadataError> {
        let bytes = serde_json::to_vec(update.metadata())
            .map_err(|_| InstalledUpdateMetadataError::Corrupt)?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(InstalledUpdateMetadataError::Corrupt);
        }
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
        fs::rename(&temporary, &final_path).map_err(|_| InstalledUpdateMetadataError::Io)?;
        for path in self.candidate_paths()? {
            if path != final_path {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }

    pub fn read(&self) -> Result<Option<UpdateMetadataV2>, InstalledUpdateMetadataError> {
        let Some(path) = self.latest_path()? else {
            return Ok(None);
        };
        let metadata = fs::symlink_metadata(&path).map_err(|_| InstalledUpdateMetadataError::Io)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_METADATA_BYTES
        {
            return Err(InstalledUpdateMetadataError::Corrupt);
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|_| InstalledUpdateMetadataError::Io)?
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| InstalledUpdateMetadataError::Io)?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(InstalledUpdateMetadataError::Corrupt);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
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
    path.file_name()?
        .to_string_lossy()
        .rsplit('.')
        .nth(1)?
        .parse()
        .ok()
}
