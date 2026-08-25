//! Crash-safe, native-owned updater transaction journal.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateInstallRecord {
    pub version: String,
    pub artifact_sha256: String,
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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRecord {
    schema_version: u32,
    state: String,
    version: String,
    artifact_sha256: String,
    staged_path: String,
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
            schema_version: SCHEMA_VERSION,
            state: state_name(record.state).to_owned(),
            version: record.version,
            artifact_sha256: record.artifact_sha256,
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
        if self.path.exists() {
            paths.push(self.path.clone());
        }
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

fn decode(wire: WireRecord) -> Result<UpdateInstallRecord, UpdateJournalError> {
    let state = match wire.state.as_str() {
        "staged" => super::UpdateInstallState::Staged,
        "restart_required" => super::UpdateInstallState::RestartRequired,
        "health_check" => super::UpdateInstallState::HealthCheck,
        "committed" => super::UpdateInstallState::Committed,
        "rolled_back" => super::UpdateInstallState::RolledBack,
        _ => return Err(UpdateJournalError::Corrupt),
    };
    let record = UpdateInstallRecord {
        version: wire.version,
        artifact_sha256: wire.artifact_sha256,
        staged_path: PathBuf::from(wire.staged_path),
        state,
    };
    (wire.schema_version == SCHEMA_VERSION)
        .then_some(record)
        .ok_or(UpdateJournalError::Corrupt)
        .and_then(|record| {
            validate_record(&record)?;
            Ok(record)
        })
}

fn validate_record(record: &UpdateInstallRecord) -> Result<(), UpdateJournalError> {
    if crate::updater::parse_version(&record.version).is_err()
        || !crate::updater::is_sha256(&record.artifact_sha256)
        || record.staged_path.as_os_str().is_empty()
        || record.staged_path.as_os_str().to_string_lossy().len() > MAX_PATH_BYTES
        || !record.staged_path.is_absolute()
    {
        return Err(UpdateJournalError::Corrupt);
    }
    Ok(())
}

const fn valid_transition(from: super::UpdateInstallState, to: super::UpdateInstallState) -> bool {
    matches!(
        (from, to),
        (
            super::UpdateInstallState::Staged,
            super::UpdateInstallState::RestartRequired
        ) | (
            super::UpdateInstallState::RestartRequired,
            super::UpdateInstallState::HealthCheck
        ) | (
            super::UpdateInstallState::HealthCheck,
            super::UpdateInstallState::Committed | super::UpdateInstallState::RolledBack
        )
    )
}

const fn state_name(state: super::UpdateInstallState) -> &'static str {
    match state {
        super::UpdateInstallState::Staged => "staged",
        super::UpdateInstallState::RestartRequired => "restart_required",
        super::UpdateInstallState::HealthCheck => "health_check",
        super::UpdateInstallState::Committed => "committed",
        super::UpdateInstallState::RolledBack => "rolled_back",
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
        .nth(1)
        .and_then(|value| value.parse().ok())
}

fn publish_no_replace(temporary: &Path, final_path: &Path) -> Result<(), UpdateJournalError> {
    #[cfg(windows)]
    {
        let source = runne_windows_native_handle::inspect_regular_file(temporary)
            .map_err(|_| UpdateJournalError::Io)?;
        runne_windows_native_handle::move_regular_file_no_replace_write_through(
            temporary,
            final_path,
            source.id(),
        )
        .map_err(|_| UpdateJournalError::Io)
    }
    #[cfg(not(windows))]
    {
        fs::rename(temporary, final_path).map_err(|_| UpdateJournalError::Io)
    }
}
