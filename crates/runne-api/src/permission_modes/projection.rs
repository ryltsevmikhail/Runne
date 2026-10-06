//! Honest selected/effective mode projection. Historical ready state is not authority.

use runne_domain::id::{ApprovalId, IntegrityDigest};
use serde::{Deserialize, Serialize};

use super::{
    PermissionContainmentV1, PermissionModeNotReadyReasonV1, PermissionModeV1,
    PermissionNetworkStateV1, PermissionPresetVersionV1,
};

/// Current selected mode and the separately admitted effective enforcement state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeStatusV1 {
    pub selected_mode: PermissionModeV1,
    pub effective: PermissionEffectiveStateV1,
    pub authorization_revision: u64,
    pub preset_version: PermissionPresetVersionV1,
    pub managed_policy_version: u64,
    pub pending_approval_ids: Vec<ApprovalId>,
    pub containment: Option<PermissionContainmentV1>,
    pub network_state: PermissionNetworkStateV1,
    pub expires_at_unix_ms: Option<i64>,
}

/// Effective mode reported independently from the selected mode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum PermissionEffectiveStateV1 {
    NotReady {
        reason: PermissionModeNotReadyReasonV1,
    },
    Ready {
        mode: PermissionModeV1,
        preset_version: PermissionPresetVersionV1,
        scope_digest: IntegrityDigest,
        containment: PermissionContainmentV1,
    },
}

/// Durable non-authoritative snapshot stored with a mode-change receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeHistoryV1 {
    pub selected_mode: PermissionModeV1,
    pub effective: PermissionEffectiveStateV1,
    pub authorization_revision: u64,
    pub preset_version: PermissionPresetVersionV1,
    pub managed_policy_version: u64,
    pub containment: Option<PermissionContainmentV1>,
    pub network_state: PermissionNetworkStateV1,
    pub expires_at_unix_ms: Option<i64>,
}

/// Idempotent result of one compare-and-set mode command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeChangeReceiptV1 {
    pub command_id: runne_domain::id::CommandId,
    pub idempotency_key: String,
    pub intent_digest: IntegrityDigest,
    pub authorization_revision: u64,
    pub selected_mode: PermissionModeV1,
    pub history: PermissionModeHistoryV1,
}
