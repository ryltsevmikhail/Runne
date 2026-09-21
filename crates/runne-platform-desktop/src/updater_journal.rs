//! Crash-safe, native-owned updater transaction journal.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use thiserror::Error;

const MAX_JOURNAL_BYTES: u64 = 16 * 1024;

#[path = "updater_journal/wire.rs"]
mod journal_wire;
#[cfg(test)]
#[path = "updater_journal/tests.rs"]
mod tests;
#[cfg(unix)]
use journal_wire::sync_parent;
use journal_wire::{
    WireRecord, decode, numbered_path, publish_no_replace, read_bounded_regular_file, sequence_any,
    sequence_of, state_name, valid_transition, validate_record,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateInstallRecord {
    pub version: String,
    pub artifact_sha256: String,
    pub metadata_sha256: Option<String>,
    pub legacy_unbound: bool,
    pub staged_path: PathBuf,
    pub state: super::UpdateInstallState,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UpdateJournalError {
    #[error("updater journal is corrupt")]
    Corrupt,
    #[error("updater journal operation failed")]
    Io,
    #[error("updater transaction does not exist")]
    NoTransaction,
    #[error("updater transaction transition is invalid")]
    InvalidTransition,
}

/// Persists only the non-secret identity and lifecycle of one staged artifact.
#[derive(Clone, Debug)]
pub struct UpdateJournal {
    path: PathBuf,
}

impl UpdateJournal {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn read(&self) -> Result<Option<UpdateInstallRecord>, UpdateJournalError> {
        let path = match self.latest_path()? {
            Some(path) => path,
            None => match self.legacy_path()? {
                Some(path) => path,
                None => return Ok(None),
            },
        };
        let bytes = read_bounded_regular_file(&path, MAX_JOURNAL_BYTES)?;
        let wire: WireRecord =
            serde_json::from_slice(&bytes).map_err(|_| UpdateJournalError::Corrupt)?;
        decode(wire).map(Some)
    }

    pub fn record_staged(
        &self,
        version: &str,
        staged: &super::StagedUpdate,
    ) -> Result<(), UpdateJournalError> {
        self.write(UpdateInstallRecord {
            version: version.to_owned(),
            artifact_sha256: staged.artifact_sha256.clone(),
            metadata_sha256: None,
            legacy_unbound: false,
            staged_path: staged.path.clone(),
            state: super::UpdateInstallState::Staged,
        })
    }

    pub fn record_staged_bound(
        &self,
        version: &str,
        staged: &super::StagedUpdate,
        metadata_sha256: String,
    ) -> Result<(), UpdateJournalError> {
        self.write(UpdateInstallRecord {
            version: version.to_owned(),
            artifact_sha256: staged.artifact_sha256.clone(),
            metadata_sha256: Some(metadata_sha256),
            legacy_unbound: false,
            staged_path: staged.path.clone(),
            state: super::UpdateInstallState::Staged,
        })
    }

    pub fn transition(&self, target: super::UpdateInstallState) -> Result<(), UpdateJournalError> {
        let mut record = self.read()?.ok_or(UpdateJournalError::NoTransaction)?;
        if !valid_transition(record.state, target) {
            return Err(UpdateJournalError::InvalidTransition);
        }
        record.state = target;
        self.write(record)
    }

    pub fn clear(&self) -> Result<(), UpdateJournalError> {
        if let Some(path) = self.legacy_path()? {
            fs::remove_file(path).map_err(|_| UpdateJournalError::Io)?;
        }
        for path in self.candidate_paths()? {
            fs::remove_file(path).map_err(|_| UpdateJournalError::Io)?;
        }
        Ok(())
    }

    pub fn discard_unbound_legacy(&self) -> Result<bool, UpdateJournalError> {
        let Some(record) = self.read()? else {
            return Ok(false);
        };
        if !record.legacy_unbound || record.metadata_sha256.is_some() {
            return Ok(false);
        }
        self.clear()?;
        Ok(true)
    }

    fn write(&self, record: UpdateInstallRecord) -> Result<(), UpdateJournalError> {
        if record.legacy_unbound {
            return Err(UpdateJournalError::Corrupt);
        }
        validate_record(&record)?;
        let parent = self.path.parent().ok_or(UpdateJournalError::Io)?;
        fs::create_dir_all(parent).map_err(|_| UpdateJournalError::Io)?;
        let sequence = self.next_sequence()?;
        let temporary = numbered_path(&self.path, sequence, "tmp");
        let final_path = numbered_path(&self.path, sequence, "json");
        let wire = WireRecord {
            schema_version: 2,
            state: state_name(record.state).to_owned(),
            version: record.version,
            artifact_sha256: record.artifact_sha256,
            metadata_sha256: record.metadata_sha256,
            staged_path: record.staged_path.to_string_lossy().into_owned(),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| UpdateJournalError::Corrupt)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| UpdateJournalError::Io)?;
        file.write_all(&bytes).map_err(|_| UpdateJournalError::Io)?;
        file.sync_all().map_err(|_| UpdateJournalError::Io)?;
        drop(file);
        publish_no_replace(&temporary, &final_path)?;
        #[cfg(unix)]
        sync_parent(parent)?;
        for path in self.candidate_paths()? {
            if path != final_path {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }

    fn latest_path(&self) -> Result<Option<PathBuf>, UpdateJournalError> {
        let mut candidates = self.candidate_paths()?;
        candidates.sort_by_key(|path| sequence_of(&self.path, path, "json"));
        Ok(candidates.pop())
    }

    fn next_sequence(&self) -> Result<u64, UpdateJournalError> {
        let Some(parent) = self.path.parent() else {
            return Err(UpdateJournalError::Io);
        };
        let entries = match fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(1),
            Err(_) => return Err(UpdateJournalError::Io),
        };
        let maximum = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter_map(|path| sequence_any(&self.path, &path))
            .max();
        maximum.map_or(Ok(1), |value| {
            value.checked_add(1).ok_or(UpdateJournalError::Corrupt)
        })
    }

    fn candidate_paths(&self) -> Result<Vec<PathBuf>, UpdateJournalError> {
        let Some(parent) = self.path.parent() else {
            return Err(UpdateJournalError::Io);
        };
        let mut paths = Vec::new();
        let entries = match fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
            Err(_) => return Err(UpdateJournalError::Io),
        };
        for entry in entries {
            let path = entry.map_err(|_| UpdateJournalError::Io)?.path();
            if sequence_of(&self.path, &path, "json").is_some() {
                paths.push(path);
            }
        }
        Ok(paths)
    }

    fn legacy_path(&self) -> Result<Option<PathBuf>, UpdateJournalError> {
        let Some(parent) = self.path.parent() else {
            return Err(UpdateJournalError::Io);
        };
        let base = self.path.file_name().ok_or(UpdateJournalError::Io)?;
        let entries = match fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(UpdateJournalError::Io),
        };
        for entry in entries {
            let path = entry.map_err(|_| UpdateJournalError::Io)?.path();
            if path.file_name().is_some_and(|name| name == base) {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }
}
