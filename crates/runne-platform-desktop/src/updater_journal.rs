//! Crash-safe, native-owned updater transaction journal.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use thiserror::Error;

const MAX_JOURNAL_BYTES: u64 = 16 * 1024;

#[path = "updater_journal/wire.rs"]
mod journal_wire;
use journal_wire::{
    WireRecord, decode, numbered_path, publish_no_replace, sequence_of, state_name, sync_parent,
    valid_transition, validate_record,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateInstallRecord {
    pub version: String,
    pub artifact_sha256: String,
    pub metadata_sha256: Option<String>,
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
        let Some(path) = self.latest_path()? else {
            if self.path.exists() {
                return Err(UpdateJournalError::Corrupt);
            }
            return Ok(None);
        };
        let metadata = fs::symlink_metadata(&path).map_err(|_| UpdateJournalError::Io)?;
        if !metadata.is_file() || metadata.len() > MAX_JOURNAL_BYTES {
            return Err(UpdateJournalError::Corrupt);
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .map_err(|_| UpdateJournalError::Io)?
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| UpdateJournalError::Io)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(UpdateJournalError::Corrupt);
        }
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
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|_| UpdateJournalError::Io)?;
        }
        for path in self.candidate_paths()? {
            fs::remove_file(path).map_err(|_| UpdateJournalError::Io)?;
        }
        Ok(())
    }

    fn write(&self, record: UpdateInstallRecord) -> Result<(), UpdateJournalError> {
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
        candidates.sort_by_key(|path| sequence_of(path));
        Ok(candidates.pop())
    }

    fn next_sequence(&self) -> Result<u64, UpdateJournalError> {
        Ok(self
            .latest_path()?
            .as_deref()
            .and_then(sequence_of)
            .unwrap_or(0)
            + 1)
    }

    fn candidate_paths(&self) -> Result<Vec<PathBuf>, UpdateJournalError> {
        let Some(parent) = self.path.parent() else {
            return Err(UpdateJournalError::Io);
        };
        let base = self
            .path
            .file_name()
            .ok_or(UpdateJournalError::Io)?
            .to_string_lossy();
        let mut paths = Vec::new();
        let entries = match fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
            Err(_) => return Err(UpdateJournalError::Io),
        };
        for entry in entries {
            let path = entry.map_err(|_| UpdateJournalError::Io)?.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.starts_with(&format!("{base}.")) && sequence_of(&path).is_some() {
                paths.push(path);
            }
        }
        Ok(paths)
    }
}
