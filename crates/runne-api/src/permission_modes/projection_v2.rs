use runne_domain::id::{ApprovalId, IntegrityDigest};
use serde::{Deserialize, Serialize};

use super::types_v2::deserialize_required_option;
use super::{
    PermissionActionMapV2, PermissionContainmentV2, PermissionModeLifecycleV2,
    PermissionModeNotReadyReasonV2, PermissionModeScopesV2, PermissionModeV1,
    PermissionNetworkStateV2, PermissionPresetVersionV1,
};

/// Effective mode and per-class admission facts from one observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PermissionEffectiveStateV2 {
    Ready {
        mode: PermissionModeV1,
        preset_version: PermissionPresetVersionV1,
        scope_digest: IntegrityDigest,
        containment: PermissionContainmentV2,
        action_map: PermissionActionMapV2,
        scopes: PermissionModeScopesV2,
    },
    NotReady {
        reason: PermissionModeNotReadyReasonV2,
        action_map: PermissionActionMapV2,
        scopes: PermissionModeScopesV2,
    },
}

impl PermissionEffectiveStateV2 {
    #[must_use]
    pub const fn action_map(&self) -> &PermissionActionMapV2 {
        match self {
            Self::Ready { action_map, .. } | Self::NotReady { action_map, .. } => action_map,
        }
    }

    #[must_use]
    pub const fn scopes(&self) -> &PermissionModeScopesV2 {
        match self {
            Self::Ready { scopes, .. } | Self::NotReady { scopes, .. } => scopes,
        }
    }
}

/// Current selected mode and effective enforcement observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeStatusV2 {
    pub selected_mode: PermissionModeV1,
    pub effective: PermissionEffectiveStateV2,
    pub authorization_revision: u64,
    pub preset_version: PermissionPresetVersionV1,
    pub managed_policy_version: u64,
    pub pending_approval_ids: Vec<ApprovalId>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub containment: Option<PermissionContainmentV2>,
    pub network_state: PermissionNetworkStateV2,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub expires_at_unix_ms: Option<i64>,
    pub observation_generation: u64,
    pub lifecycle: PermissionModeLifecycleV2,
}
