use runne_domain::id::{CommandId, IntegrityDigest};
use serde::{Deserialize, Serialize};

use super::types_v2::deserialize_required_option;
use super::{
    PermissionContainmentV2, PermissionEffectiveStateV2, PermissionModeLifecycleV2,
    PermissionModeV1, PermissionNetworkStateV2, PermissionPresetVersionV1,
};

/// Fields for the owner-provided status snapshot captured with a receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeHistoryV2 {
    pub selected_mode: PermissionModeV1,
    pub effective: PermissionEffectiveStateV2,
    pub authorization_revision: u64,
    pub preset_version: PermissionPresetVersionV1,
    pub managed_policy_version: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub containment: Option<PermissionContainmentV2>,
    pub network_state: PermissionNetworkStateV2,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub expires_at_unix_ms: Option<i64>,
    pub observation_generation: u64,
    pub lifecycle: PermissionModeLifecycleV2,
}

impl PermissionModeHistoryV2 {
    /// Copies status facts; the caller commits this snapshot atomically with its receipt.
    #[must_use]
    pub fn capture(status: &super::PermissionModeStatusV2) -> Self {
        Self {
            selected_mode: status.selected_mode,
            effective: status.effective.clone(),
            authorization_revision: status.authorization_revision,
            preset_version: status.preset_version,
            managed_policy_version: status.managed_policy_version,
            containment: status.containment,
            network_state: status.network_state,
            expires_at_unix_ms: status.expires_at_unix_ms,
            observation_generation: status.observation_generation,
            lifecycle: status.lifecycle,
        }
    }

    #[must_use]
    pub const fn action_map(&self) -> &super::PermissionActionMapV2 {
        self.effective.action_map()
    }

    #[must_use]
    pub const fn scopes(&self) -> &super::PermissionModeScopesV2 {
        self.effective.scopes()
    }
}

/// V2 mode-change receipt; its history is capture-time evidence, not authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeChangeReceiptV2 {
    pub command_id: CommandId,
    pub idempotency_key: String,
    pub intent_digest: IntegrityDigest,
    pub authorization_revision: u64,
    pub selected_mode: PermissionModeV1,
    pub history: PermissionModeHistoryV2,
}
