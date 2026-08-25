use serde::{Deserialize, Serialize};

use super::{ProviderCredentialProviderV2, ProviderCredentialValidationErrorV2};

/// Closed safe credential state exposed to Desktop.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialStateV2 {
    Configured,
    Missing,
    AccessDenied,
    Unsupported,
    Unavailable,
}

/// Closed readiness state for the current lifecycle revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialReadinessV2 {
    Ready,
    Missing,
    Stale,
    Unavailable,
    Unsupported,
    AccessDenied,
    Conflict,
    InvariantFailure,
}

/// Safe verification projection kept separate from credential readiness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialVerificationStateV2 {
    NotVerified,
    LocalVerified,
    RemoteVerified,
    Failed,
    Unsupported,
    Unavailable,
    AccessDenied,
    Stale,
}

/// Renderer-visible pending operation without durable internal identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialPendingOperationV2 {
    Pairing,
    Rotating,
    Revoking,
    Reconciling,
    Verifying,
}

/// Safe terminal or error disposition; no native backend detail is exposed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialLastDispositionV2 {
    Completed,
    AccessDenied,
    Unsupported,
    Unavailable,
    Conflict,
    InvalidRequest,
    InvariantFailure,
}

/// Authoritative metadata-only provider credential projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", try_from = "SafeSnapshotWire")]
pub struct ProviderCredentialSafeSnapshotV2 {
    provider_id: ProviderCredentialProviderV2,
    credential_state: ProviderCredentialStateV2,
    readiness: ProviderCredentialReadinessV2,
    lifecycle_revision: u64,
    readiness_revision: u64,
    observed_at: i64,
    verification_state: ProviderCredentialVerificationStateV2,
    verification_revision: u64,
    pending_operation: Option<ProviderCredentialPendingOperationV2>,
    cleanup_pending: bool,
    last_disposition: Option<ProviderCredentialLastDispositionV2>,
}

impl ProviderCredentialSafeSnapshotV2 {
    /// Constructs one validated renderer-safe provider projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: ProviderCredentialProviderV2,
        credential_state: ProviderCredentialStateV2,
        readiness: ProviderCredentialReadinessV2,
        lifecycle_revision: u64,
        readiness_revision: u64,
        observed_at: i64,
        verification_state: ProviderCredentialVerificationStateV2,
        verification_revision: u64,
        pending_operation: Option<ProviderCredentialPendingOperationV2>,
        cleanup_pending: bool,
        last_disposition: Option<ProviderCredentialLastDispositionV2>,
    ) -> Result<Self, ProviderCredentialValidationErrorV2> {
        Self::try_from(SafeSnapshotWire {
            provider_id,
            credential_state,
            readiness,
            lifecycle_revision,
            readiness_revision,
            observed_at,
            verification_state,
            verification_revision,
            pending_operation,
            cleanup_pending,
            last_disposition,
        })
    }

    pub const fn provider_id(&self) -> ProviderCredentialProviderV2 {
        self.provider_id
    }
    pub const fn credential_state(&self) -> ProviderCredentialStateV2 {
        self.credential_state
    }
    pub const fn readiness(&self) -> ProviderCredentialReadinessV2 {
        self.readiness
    }
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }
    pub const fn readiness_revision(&self) -> u64 {
        self.readiness_revision
    }
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }
    pub const fn verification_state(&self) -> ProviderCredentialVerificationStateV2 {
        self.verification_state
    }
    pub const fn verification_revision(&self) -> u64 {
        self.verification_revision
    }
    pub const fn pending_operation(&self) -> Option<ProviderCredentialPendingOperationV2> {
        self.pending_operation
    }
    pub const fn cleanup_pending(&self) -> bool {
        self.cleanup_pending
    }
    pub const fn last_disposition(&self) -> Option<ProviderCredentialLastDispositionV2> {
        self.last_disposition
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SafeSnapshotWire {
    provider_id: ProviderCredentialProviderV2,
    credential_state: ProviderCredentialStateV2,
    readiness: ProviderCredentialReadinessV2,
    lifecycle_revision: u64,
    readiness_revision: u64,
    observed_at: i64,
    verification_state: ProviderCredentialVerificationStateV2,
    verification_revision: u64,
    pending_operation: Option<ProviderCredentialPendingOperationV2>,
    cleanup_pending: bool,
    last_disposition: Option<ProviderCredentialLastDispositionV2>,
}

impl TryFrom<SafeSnapshotWire> for ProviderCredentialSafeSnapshotV2 {
    type Error = ProviderCredentialValidationErrorV2;

    fn try_from(value: SafeSnapshotWire) -> Result<Self, Self::Error> {
        let verification_revision_valid = match value.verification_state {
            ProviderCredentialVerificationStateV2::NotVerified => value.verification_revision == 0,
            _ => value.verification_revision > 0,
        };
        if value.lifecycle_revision == 0
            || value.readiness_revision == 0
            || value.observed_at < 0
            || !verification_revision_valid
        {
            return Err(ProviderCredentialValidationErrorV2::InvalidSnapshot);
        }
        Ok(Self {
            provider_id: value.provider_id,
            credential_state: value.credential_state,
            readiness: value.readiness,
            lifecycle_revision: value.lifecycle_revision,
            readiness_revision: value.readiness_revision,
            observed_at: value.observed_at,
            verification_state: value.verification_state,
            verification_revision: value.verification_revision,
            pending_operation: value.pending_operation,
            cleanup_pending: value.cleanup_pending,
            last_disposition: value.last_disposition,
        })
    }
}
