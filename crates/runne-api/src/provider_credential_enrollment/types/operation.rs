use serde::{Deserialize, Serialize};

use super::{
    ProviderCredentialLastDispositionV2, ProviderCredentialOperationHandleV2,
    ProviderCredentialProviderV2, ProviderCredentialValidationErrorV2,
};

/// Closed kind for enrollment and explicit verification operation responses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialOperationKindV2 {
    Pair,
    Revoke,
    MigrateLegacy,
    VerifyLocal,
    VerifyRemote,
}

impl ProviderCredentialOperationKindV2 {
    const fn requires_broker(self) -> bool {
        matches!(self, Self::Pair | Self::Revoke | Self::MigrateLegacy)
    }
}

/// Closed durable operation state safe for authenticated resume responses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialOperationStateV2 {
    Prepared,
    Claimed,
    NativeEffectObserved,
    ReadbackVerified,
    Completed,
    Failed,
    Expired,
    Cancelled,
    Tombstoned,
}

/// Safe operation response used by begin, resume and explicit verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", try_from = "OperationSnapshotWire")]
pub struct ProviderCredentialOperationSnapshotV2 {
    #[serde(rename = "operationId")]
    operation_handle: ProviderCredentialOperationHandleV2,
    broker_rendezvous_id: Option<String>,
    provider_id: ProviderCredentialProviderV2,
    operation_kind: ProviderCredentialOperationKindV2,
    state: ProviderCredentialOperationStateV2,
    lifecycle_revision: u64,
    readiness_revision: u64,
    cleanup_pending: bool,
    last_disposition: Option<ProviderCredentialLastDispositionV2>,
}

impl ProviderCredentialOperationSnapshotV2 {
    /// Constructs one validated safe operation response.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_handle: ProviderCredentialOperationHandleV2,
        broker_rendezvous_id: Option<String>,
        provider_id: ProviderCredentialProviderV2,
        operation_kind: ProviderCredentialOperationKindV2,
        state: ProviderCredentialOperationStateV2,
        lifecycle_revision: u64,
        readiness_revision: u64,
        cleanup_pending: bool,
        last_disposition: Option<ProviderCredentialLastDispositionV2>,
    ) -> Result<Self, ProviderCredentialValidationErrorV2> {
        Self::try_from(OperationSnapshotWire {
            operation_handle,
            broker_rendezvous_id,
            provider_id,
            operation_kind,
            state,
            lifecycle_revision,
            readiness_revision,
            cleanup_pending,
            last_disposition,
        })
    }

    pub const fn operation_handle(&self) -> ProviderCredentialOperationHandleV2 {
        self.operation_handle
    }
    pub fn broker_rendezvous_id(&self) -> Option<&str> {
        self.broker_rendezvous_id.as_deref()
    }
    pub const fn provider_id(&self) -> ProviderCredentialProviderV2 {
        self.provider_id
    }
    pub const fn operation_kind(&self) -> ProviderCredentialOperationKindV2 {
        self.operation_kind
    }
    pub const fn state(&self) -> ProviderCredentialOperationStateV2 {
        self.state
    }
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }
    pub const fn readiness_revision(&self) -> u64 {
        self.readiness_revision
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
struct OperationSnapshotWire {
    #[serde(rename = "operationId")]
    operation_handle: ProviderCredentialOperationHandleV2,
    broker_rendezvous_id: Option<String>,
    provider_id: ProviderCredentialProviderV2,
    operation_kind: ProviderCredentialOperationKindV2,
    state: ProviderCredentialOperationStateV2,
    lifecycle_revision: u64,
    readiness_revision: u64,
    cleanup_pending: bool,
    last_disposition: Option<ProviderCredentialLastDispositionV2>,
}

impl TryFrom<OperationSnapshotWire> for ProviderCredentialOperationSnapshotV2 {
    type Error = ProviderCredentialValidationErrorV2;

    fn try_from(value: OperationSnapshotWire) -> Result<Self, Self::Error> {
        let broker_valid = match value.broker_rendezvous_id.as_deref() {
            Some(id) => value.operation_kind.requires_broker() && valid_public_id(id),
            None => true,
        };
        if value.lifecycle_revision == 0 || value.readiness_revision == 0 || !broker_valid {
            return Err(ProviderCredentialValidationErrorV2::InvalidSnapshot);
        }
        Ok(Self {
            operation_handle: value.operation_handle,
            broker_rendezvous_id: value.broker_rendezvous_id,
            provider_id: value.provider_id,
            operation_kind: value.operation_kind,
            state: value.state,
            lifecycle_revision: value.lifecycle_revision,
            readiness_revision: value.readiness_revision,
            cleanup_pending: value.cleanup_pending,
            last_disposition: value.last_disposition,
        })
    }
}

fn valid_public_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}
