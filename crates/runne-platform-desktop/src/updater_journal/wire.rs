use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{UpdateInstallRecord, UpdateJournalError};

const MAX_PATH_BYTES: usize = 4 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WireRecord {
    pub(super) schema_version: u32,
    pub(super) state: String,
    pub(super) version: String,
    pub(super) artifact_sha256: String,
    #[serde(default)]
    pub(super) metadata_sha256: Option<String>,
    pub(super) staged_path: String,
}

pub(super) fn decode(wire: WireRecord) -> Result<UpdateInstallRecord, UpdateJournalError> {
    let state = match wire.state.as_str() {
        "staged" => super::super::UpdateInstallState::Staged,
        "restart_required" => super::super::UpdateInstallState::RestartRequired,
        "health_check" => super::super::UpdateInstallState::HealthCheck,
        "committed" => super::super::UpdateInstallState::Committed,
        "rolled_back" => super::super::UpdateInstallState::RolledBack,
        _ => return Err(UpdateJournalError::Corrupt),
    };
    let record = UpdateInstallRecord {
        version: wire.version,
        artifact_sha256: wire.artifact_sha256,
        metadata_sha256: wire.metadata_sha256,
        staged_path: PathBuf::from(wire.staged_path),
        state,
        legacy_unbound: matches!(wire.schema_version, 1),
    };
    (matches!(wire.schema_version, 1 | 2)
        && (wire.schema_version == 2 || record.metadata_sha256.is_none()))
    .then_some(record)
    .ok_or(UpdateJournalError::Corrupt)
    .and_then(|record| {
        validate_record(&record)?;
        Ok(record)
    })
}

pub(super) fn validate_record(record: &UpdateInstallRecord) -> Result<(), UpdateJournalError> {
    if crate::updater::parse_version(&record.version).is_err()
        || !crate::updater::is_sha256(&record.artifact_sha256)
        || record
            .metadata_sha256
            .as_deref()
            .is_some_and(|digest| !crate::updater::is_sha256(digest))
        || record.staged_path.as_os_str().is_empty()
        || record.staged_path.as_os_str().to_string_lossy().len() > MAX_PATH_BYTES
        || !record.staged_path.is_absolute()
    {
        return Err(UpdateJournalError::Corrupt);
    }
    Ok(())
}

pub(super) const fn valid_transition(
    from: super::super::UpdateInstallState,
    to: super::super::UpdateInstallState,
) -> bool {
    matches!(
        (from, to),
        (
            super::super::UpdateInstallState::Staged,
            super::super::UpdateInstallState::RestartRequired
        ) | (
            super::super::UpdateInstallState::RestartRequired,
            super::super::UpdateInstallState::Staged
                | super::super::UpdateInstallState::HealthCheck
        ) | (
            super::super::UpdateInstallState::HealthCheck,
            super::super::UpdateInstallState::Committed
                | super::super::UpdateInstallState::RolledBack
        )
    )
}

pub(super) const fn state_name(state: super::super::UpdateInstallState) -> &'static str {
    match state {
        super::super::UpdateInstallState::Staged => "staged",
        super::super::UpdateInstallState::RestartRequired => "restart_required",
        super::super::UpdateInstallState::HealthCheck => "health_check",
        super::super::UpdateInstallState::Committed => "committed",
        super::super::UpdateInstallState::RolledBack => "rolled_back",
    }
}

pub(super) fn numbered_path(base: &Path, sequence: u64, suffix: &str) -> PathBuf {
    let mut path = base.as_os_str().to_os_string();
    path.push(format!(".{sequence}.{suffix}"));
    PathBuf::from(path)
}

pub(super) fn sequence_of(base: &Path, path: &Path, suffix: &str) -> Option<u64> {
    let base = base.file_name()?.to_str()?;
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix(base)?.strip_prefix('.')?;
    let (digits, actual_suffix) = rest.split_once('.')?;
    (actual_suffix == suffix
        && !digits.is_empty()
        && digits.parse::<u64>().ok()?.to_string() == digits)
        .then(|| digits.parse().ok())?
}

pub(super) fn sequence_any(base: &Path, path: &Path) -> Option<u64> {
    sequence_of(base, path, "json").or_else(|| sequence_of(base, path, "tmp"))
}

pub(super) fn read_bounded_regular_file(
    path: &Path,
    maximum: u64,
) -> Result<Vec<u8>, UpdateJournalError> {
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
    let file = file.map_err(|_| UpdateJournalError::Io)?;
    let metadata = file.metadata().map_err(|_| UpdateJournalError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(UpdateJournalError::Corrupt);
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(&metadata) != 1 {
        return Err(UpdateJournalError::Corrupt);
    }
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(&metadata) & 0x400 != 0 {
        return Err(UpdateJournalError::Corrupt);
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UpdateJournalError::Io)?;
    (bytes.len() as u64 <= maximum)
        .then_some(bytes)
        .ok_or(UpdateJournalError::Corrupt)
}

pub(super) fn publish_no_replace(
    temporary: &Path,
    final_path: &Path,
) -> Result<(), UpdateJournalError> {
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

pub(super) fn sync_parent(parent: &Path) -> Result<(), UpdateJournalError> {
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| UpdateJournalError::Io)?;
    #[cfg(windows)]
    let _ = parent;
    Ok(())
}
