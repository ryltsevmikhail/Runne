//! Signed update metadata verification and crash-safe artifact staging.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::redundant_pub_crate)]

use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePayloadV1 {
    pub schema_version: u32,
    pub product_id: String,
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub artifact_sha256: String,
    pub artifact_size: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMetadataV1 {
    pub payload: UpdatePayloadV1,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTarget {
    pub product_id: String,
    pub platform: String,
    pub arch: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdate {
    pub payload: UpdatePayloadV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedUpdate {
    pub path: PathBuf,
    pub artifact_sha256: String,
}

/// Explicit owner-confirmed installation transaction state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateInstallState {
    /// Artifact is staged and awaits a controlled runtime restart.
    Staged,
    /// Restart has been requested and post-restart health is required.
    RestartRequired,
    /// Runtime health/reconciliation is being checked.
    HealthCheck,
    /// New version passed the post-restart health gate.
    Committed,
    /// New version failed health and must remain unapplied.
    RolledBack,
}

/// Rejected updater transaction transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum UpdateInstallError {
    #[error("active task runs require explicit update confirmation")]
    ActiveTaskRuns,
    #[error("update transaction state transition is invalid")]
    InvalidTransition,
    #[error("staged update digest is invalid")]
    InvalidDigest,
}

/// In-memory transaction record for one staged update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateInstallPlan {
    staged: StagedUpdate,
    state: UpdateInstallState,
}

impl UpdateInstallPlan {
    /// Admits a staged artifact only after the active-work impact is confirmed.
    pub fn prepare(
        staged: StagedUpdate,
        active_task_runs: u64,
        confirm_active_task_runs: bool,
    ) -> Result<Self, UpdateInstallError> {
        if active_task_runs > 0 && !confirm_active_task_runs {
            return Err(UpdateInstallError::ActiveTaskRuns);
        }
        if !is_sha256(&staged.artifact_sha256) {
            return Err(UpdateInstallError::InvalidDigest);
        }
        Ok(Self {
            staged,
            state: UpdateInstallState::Staged,
        })
    }

    /// Returns the current transaction state.
    #[must_use]
    pub const fn state(&self) -> UpdateInstallState {
        self.state
    }

    /// Returns the staged artifact identity without exposing its bytes.
    #[must_use]
    pub const fn staged(&self) -> &StagedUpdate {
        &self.staged
    }

    /// Moves the transaction into the restart-required state.
    pub fn begin_restart(mut self) -> Result<Self, UpdateInstallError> {
        if self.state != UpdateInstallState::Staged {
            return Err(UpdateInstallError::InvalidTransition);
        }
        self.state = UpdateInstallState::RestartRequired;
        Ok(self)
    }

    /// Opens the post-restart health/reconciliation gate.
    pub fn begin_health_check(mut self) -> Result<Self, UpdateInstallError> {
        if self.state != UpdateInstallState::RestartRequired {
            return Err(UpdateInstallError::InvalidTransition);
        }
        self.state = UpdateInstallState::HealthCheck;
        Ok(self)
    }

    /// Commits only healthy restart evidence; failure becomes explicit rollback.
    pub fn complete_health(mut self, healthy: bool) -> Result<Self, UpdateInstallError> {
        if self.state != UpdateInstallState::HealthCheck {
            return Err(UpdateInstallError::InvalidTransition);
        }
        self.state = if healthy {
            UpdateInstallState::Committed
        } else {
            UpdateInstallState::RolledBack
        };
        Ok(self)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UpdateVerificationError {
    #[error("update metadata is invalid")]
    InvalidMetadata,
    #[error("update signature is invalid")]
    InvalidSignature,
    #[error("update trust root is invalid")]
    InvalidTrustRoot,
    #[error("update target does not match this desktop")]
    TargetMismatch,
    #[error("update is expired")]
    Expired,
    #[error("update is below the rollback floor")]
    Rollback,
    #[error("update artifact is invalid")]
    InvalidArtifact,
    #[error("update artifact could not be staged")]
    StageFailed,
}

pub fn verify_update(
    metadata: &UpdateMetadataV1,
    trust_root: &[u8; 32],
    target: &UpdateTarget,
    now_unix_seconds: u64,
    current_version: &str,
    rollback_floor: &str,
) -> Result<VerifiedUpdate, UpdateVerificationError> {
    let payload = &metadata.payload;
    if payload.schema_version != 1
        || payload.product_id != target.product_id
        || payload.platform != target.platform
        || payload.arch != target.arch
        || payload.expires_at_unix_seconds <= now_unix_seconds
        || !is_sha256(&payload.artifact_sha256)
    {
        return Err(if payload.expires_at_unix_seconds <= now_unix_seconds {
            UpdateVerificationError::Expired
        } else if payload.product_id != target.product_id
            || payload.platform != target.platform
            || payload.arch != target.arch
        {
            UpdateVerificationError::TargetMismatch
        } else {
            UpdateVerificationError::InvalidMetadata
        });
    }
    if payload.artifact_size == 0 || payload.artifact_size > MAX_ARTIFACT_BYTES {
        return Err(UpdateVerificationError::InvalidArtifact);
    }
    let key = VerifyingKey::from_bytes(trust_root)
        .map_err(|_| UpdateVerificationError::InvalidTrustRoot)?;
    let signature_bytes =
        hex::decode(&metadata.signature).map_err(|_| UpdateVerificationError::InvalidSignature)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| UpdateVerificationError::InvalidSignature)?;
    let signed_payload =
        serde_json::to_vec(payload).map_err(|_| UpdateVerificationError::InvalidMetadata)?;
    key.verify(&signed_payload, &signature)
        .map_err(|_| UpdateVerificationError::InvalidSignature)?;
    let version = parse_version(&payload.version)?;
    if version < parse_version(current_version)? || version < parse_version(rollback_floor)? {
        return Err(UpdateVerificationError::Rollback);
    }
    Ok(VerifiedUpdate {
        payload: payload.clone(),
    })
}

pub fn stage_verified_artifact(
    destination: &Path,
    update: &VerifiedUpdate,
    bytes: &[u8],
) -> Result<StagedUpdate, UpdateVerificationError> {
    if u64::try_from(bytes.len()).ok() != Some(update.payload.artifact_size)
        || sha256_hex(bytes) != update.payload.artifact_sha256
    {
        return Err(UpdateVerificationError::InvalidArtifact);
    }
    if destination.exists() {
        return Err(UpdateVerificationError::StageFailed);
    }
    let mut temporary = destination.to_path_buf();
    temporary.set_extension("staged.tmp");
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| UpdateVerificationError::StageFailed)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| UpdateVerificationError::StageFailed)?;
        std::fs::rename(&temporary, destination)
            .map_err(|_| UpdateVerificationError::StageFailed)?;
        Ok(StagedUpdate {
            path: destination.to_path_buf(),
            artifact_sha256: update.payload.artifact_sha256.clone(),
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn parse_version(value: &str) -> Result<[u64; 3], UpdateVerificationError> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || part.starts_with('0') && part.len() > 1)
    {
        return Err(UpdateVerificationError::InvalidMetadata);
    }
    let mut parsed = [0; 3];
    for (index, part) in parts.into_iter().enumerate() {
        parsed[index] = part
            .parse()
            .map_err(|_| UpdateVerificationError::InvalidMetadata)?;
    }
    Ok(parsed)
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
