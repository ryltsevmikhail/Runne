//! Persistent monotonic trust floor for updater metadata and installed releases.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: u32 = 1;
const MAX_TRUST_BYTES: u64 = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTrustState {
    pub root_version: u64,
    pub snapshot_version: u64,
    pub installed_version: String,
    pub rollback_floor: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum UpdateTrustError {
    #[error("updater trust state is corrupt")]
    Corrupt,
    #[error("updater trust state operation failed")]
    Io,
    #[error("updater trust state is not initialized")]
    Uninitialized,
    #[error("updater metadata would move the trust floor backwards")]
    Rollback,
    #[error("updater trust state transition is invalid")]
    InvalidTransition,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireTrustState {
    schema_version: u32,
    root_version: u64,
    snapshot_version: u64,
    installed_version: String,
    rollback_floor: String,
}

/// Native-owned monotonic updater state. It contains no URLs or artifacts.
#[derive(Clone, Debug)]
pub struct UpdateTrustJournal {
    path: PathBuf,
}

impl UpdateTrustJournal {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn initialize(
        &self,
        installed_version: &str,
        rollback_floor: &str,
    ) -> Result<UpdateTrustState, UpdateTrustError> {
        let state = UpdateTrustState {
            root_version: 0,
            snapshot_version: 0,
            installed_version: installed_version.to_owned(),
            rollback_floor: rollback_floor.to_owned(),
        };
        validate(&state)?;
        if self.read()?.is_some() {
            return Err(UpdateTrustError::InvalidTransition);
        }
        self.write(&state)?;
        Ok(state)
    }

    pub fn read(&self) -> Result<Option<UpdateTrustState>, UpdateTrustError> {
        let Some(path) = self.latest_path()? else {
            return Ok(None);
        };
        let metadata = fs::symlink_metadata(&path).map_err(|_| UpdateTrustError::Io)?;
        if !metadata.is_file() || metadata.len() > MAX_TRUST_BYTES {
            return Err(UpdateTrustError::Corrupt);
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|_| UpdateTrustError::Io)?
            .take(MAX_TRUST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| UpdateTrustError::Io)?;
        if bytes.len() as u64 > MAX_TRUST_BYTES {
            return Err(UpdateTrustError::Corrupt);
        }
        let wire: WireTrustState =
            serde_json::from_slice(&bytes).map_err(|_| UpdateTrustError::Corrupt)?;
        if wire.schema_version != SCHEMA_VERSION {
            return Err(UpdateTrustError::Corrupt);
        }
        let state = UpdateTrustState {
            root_version: wire.root_version,
            snapshot_version: wire.snapshot_version,
            installed_version: wire.installed_version,
            rollback_floor: wire.rollback_floor,
        };
        validate(&state)?;
        Ok(Some(state))
    }

    pub fn accept_metadata(
        &self,
        root_version: u64,
        snapshot_version: u64,
        target_version: &str,
    ) -> Result<UpdateTrustState, UpdateTrustError> {
        let mut state = self.read()?.ok_or(UpdateTrustError::Uninitialized)?;
        let target = version(target_version)?;
        if root_version < state.root_version
            || snapshot_version < state.snapshot_version
            || target < version(&state.installed_version)?
            || target < version(&state.rollback_floor)?
        {
            return Err(UpdateTrustError::Rollback);
        }
        state.root_version = root_version;
        state.snapshot_version = snapshot_version;
        self.write(&state)?;
        Ok(state)
    }

    pub fn commit_install(
        &self,
        installed_version: &str,
    ) -> Result<UpdateTrustState, UpdateTrustError> {
        let mut state = self.read()?.ok_or(UpdateTrustError::Uninitialized)?;
        if version(installed_version)? < version(&state.installed_version)?
            || version(installed_version)? < version(&state.rollback_floor)?
        {
            return Err(UpdateTrustError::Rollback);
        }
        installed_version.clone_into(&mut state.installed_version);
        self.write(&state)?;
        Ok(state)
    }

    fn write(&self, state: &UpdateTrustState) -> Result<(), UpdateTrustError> {
        validate(state)?;
        let parent = self.path.parent().ok_or(UpdateTrustError::Io)?;
        fs::create_dir_all(parent).map_err(|_| UpdateTrustError::Io)?;
        let sequence = self.next_sequence()?;
        let temporary = numbered_path(&self.path, sequence, "tmp");
        let final_path = numbered_path(&self.path, sequence, "json");
        let bytes = serde_json::to_vec(&WireTrustState {
            schema_version: SCHEMA_VERSION,
            root_version: state.root_version,
            snapshot_version: state.snapshot_version,
            installed_version: state.installed_version.clone(),
            rollback_floor: state.rollback_floor.clone(),
        })
        .map_err(|_| UpdateTrustError::Corrupt)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| UpdateTrustError::Io)?;
        file.write_all(&bytes).map_err(|_| UpdateTrustError::Io)?;
        file.sync_all().map_err(|_| UpdateTrustError::Io)?;
        drop(file);
        fs::rename(&temporary, &final_path).map_err(|_| UpdateTrustError::Io)?;
        for path in self.candidate_paths()? {
            if path != final_path {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }

    fn latest_path(&self) -> Result<Option<PathBuf>, UpdateTrustError> {
        let mut paths = self.candidate_paths()?;
        paths.sort_by_key(|path| sequence_of(path));
        Ok(paths.pop())
    }

    fn next_sequence(&self) -> Result<u64, UpdateTrustError> {
        Ok(self
            .latest_path()?
            .as_deref()
            .and_then(sequence_of)
            .unwrap_or(0)
            + 1)
    }

    fn candidate_paths(&self) -> Result<Vec<PathBuf>, UpdateTrustError> {
        let Some(parent) = self.path.parent() else {
            return Err(UpdateTrustError::Io);
        };
        let base = self
            .path
            .file_name()
            .ok_or(UpdateTrustError::Io)?
            .to_string_lossy();
        let entries = match fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(UpdateTrustError::Io),
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

fn validate(state: &UpdateTrustState) -> Result<(), UpdateTrustError> {
    if version(&state.installed_version).is_err()
        || version(&state.rollback_floor).is_err()
        || version(&state.installed_version)? < version(&state.rollback_floor)?
    {
        return Err(UpdateTrustError::Corrupt);
    }
    Ok(())
}

fn version(value: &str) -> Result<[u64; 3], UpdateTrustError> {
    crate::updater::parse_version(value).map_err(|_| UpdateTrustError::Corrupt)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_journal_is_monotonic_and_restart_safe() {
        let directory = tempfile::tempdir().unwrap();
        let journal = UpdateTrustJournal::new(directory.path().join("trust.json"));
        journal.initialize("1.0.0", "1.0.0").unwrap();
        journal.accept_metadata(3, 4, "1.2.0").unwrap();
        assert_eq!(journal.read().unwrap().unwrap().snapshot_version, 4);
        assert_eq!(
            journal.accept_metadata(2, 5, "1.3.0"),
            Err(UpdateTrustError::Rollback)
        );
        journal.commit_install("1.2.0").unwrap();
        assert_eq!(journal.read().unwrap().unwrap().installed_version, "1.2.0");
        assert_eq!(
            journal.commit_install("1.1.0"),
            Err(UpdateTrustError::Rollback)
        );
    }
}
