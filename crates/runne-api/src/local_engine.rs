//! Local Engine runtime-client API surface (Plan Task 14).
//!
//! Contract types mirroring the Local Engine standalone types (see
//! `PRODUCT_COMPOSITION_CONTRACTS.md`): the authenticated owner reads
//! the local-engine status — activation, selection, installations and
//! the last generation phase — without ever seeing filesystem paths,
//! protocol internals or credentials.

use serde::{Deserialize, Serialize};
use std::fmt;

const MAX_TEXT_BYTES: usize = 128;
const MAX_INSTALLATIONS: usize = 32;
const MAX_DIGEST_HEX: usize = 64;

/// Closed local-engine readiness disposition (mirrors provider
/// readiness; local execution adds no credential dimension).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEngineReadinessV1 {
    /// Activation selected, backend admitted, generation available.
    Ready,
    /// Local Engine is not the runtime's selected activation.
    NotSelected,
    /// The local execution backend is unavailable.
    BackendUnavailable,
}

/// One installed local model known to the catalog authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalInstallationSnapshotV1 {
    model_id: String,
    model_revision: String,
    /// `sha256:<hex>` of the immutable manifest.
    manifest_digest: String,
    /// Pinned qualification-matrix revision; empty = unqualified
    /// (cannot back a capability claim).
    matrix_revision: String,
    active_refs: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalInstallationValidationError {
    InvalidText,
    InvalidDigest,
}

impl fmt::Display for LocalInstallationValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidText => formatter.write_str("installation contains invalid text"),
            Self::InvalidDigest => {
                formatter.write_str("installation manifest digest is not sha256 hex")
            }
        }
    }
}

impl std::error::Error for LocalInstallationValidationError {}

impl LocalInstallationSnapshotV1 {
    /// Constructs a validated installation snapshot.
    pub fn new(
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        manifest_digest: impl Into<String>,
        matrix_revision: impl Into<String>,
        active_refs: u32,
    ) -> Result<Self, LocalInstallationValidationError> {
        let model_id = model_id.into();
        let model_revision = model_revision.into();
        let manifest_digest = manifest_digest.into();
        let matrix_revision = matrix_revision.into();
        let valid = |s: &str| !s.is_empty() && s.len() <= MAX_TEXT_BYTES;
        if !valid(&model_id)
            || !valid(&model_revision)
            || manifest_digest.len() > MAX_DIGEST_HEX + 7
        {
            return Err(LocalInstallationValidationError::InvalidText);
        }
        let hex_part = manifest_digest
            .strip_prefix("sha256:")
            .ok_or(LocalInstallationValidationError::InvalidDigest)?;
        if hex_part.len() != MAX_DIGEST_HEX
            || !hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(LocalInstallationValidationError::InvalidDigest);
        }
        // An unqualified install is representable, but it cannot carry
        // references (it cannot back a capability claim).
        if matrix_revision.is_empty() && active_refs > 0 {
            return Err(LocalInstallationValidationError::InvalidText);
        }
        Ok(Self {
            model_id,
            model_revision,
            manifest_digest,
            matrix_revision,
            active_refs,
        })
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn matrix_revision(&self) -> &str {
        &self.matrix_revision
    }
}

/// Last known generation phase for the canonical conversation host.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEngineGenerationPhaseV1 {
    Idle,
    Streaming,
    Cancelling,
    Completed,
    Uncertain,
}

/// Authenticated Local Engine status snapshot (owner-read only).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalEngineStatusSnapshotV1 {
    /// Selected activation mode, e.g. `local_engine_text_v1`; empty
    /// when no local activation is selected.
    activation_mode: String,
    readiness: LocalEngineReadinessV1,
    installations: Vec<LocalInstallationSnapshotV1>,
    generation: Option<LocalEngineGenerationPhaseV1>,
}

impl LocalEngineStatusSnapshotV1 {
    pub fn new(
        activation_mode: impl Into<String>,
        readiness: LocalEngineReadinessV1,
        installations: Vec<LocalInstallationSnapshotV1>,
        generation: Option<LocalEngineGenerationPhaseV1>,
    ) -> Result<Self, LocalInstallationValidationError> {
        let activation_mode = activation_mode.into();
        if activation_mode.len() > MAX_TEXT_BYTES {
            return Err(LocalInstallationValidationError::InvalidText);
        }
        if installations.len() > MAX_INSTALLATIONS {
            return Err(LocalInstallationValidationError::InvalidText);
        }
        let not_selected = readiness == LocalEngineReadinessV1::NotSelected;
        let activation_empty = activation_mode.is_empty();
        if not_selected != activation_empty {
            return Err(LocalInstallationValidationError::InvalidText);
        }
        Ok(Self {
            activation_mode,
            readiness,
            installations,
            generation,
        })
    }

    /// Returns the selected activation mode (empty = none selected).
    pub fn activation_mode(&self) -> &str {
        &self.activation_mode
    }

    /// Returns the readiness disposition.
    pub const fn readiness(&self) -> LocalEngineReadinessV1 {
        self.readiness
    }
}
