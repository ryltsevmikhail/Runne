use serde::{Deserialize, Serialize};

/// The fixed action classes projected by the public permission contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionActionV2 {
    FsRead,
    FsCreate,
    FsWrite,
    FsDelete,
    ProcessStart,
    NetworkUse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionManagedDecisionV2 {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionPresetBehaviorV2 {
    NoPresetPrompt,
    ExactApprovalRequired,
    PerEffectEvaluation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionEnforcementUnavailableReasonV2 {
    NativeContainmentUnavailable,
    CompositePolicyUnenforceable,
    UnsupportedEffect,
    CurrentEvidenceUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PermissionEnforcementAvailabilityV2 {
    Native,
    MediatedOnly,
    Unavailable {
        reason: PermissionEnforcementUnavailableReasonV2,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionApprovalReasonV2 {
    ManagedAsk,
    Preset,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionDeniedReasonV2 {
    ManagedDeny,
    OutsideEffectiveScope,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionDispositionUnavailableReasonV2 {
    EnforcementUnavailable,
    PolicyUnavailable,
    StaleObservation,
    Reconciling,
    PresetUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PermissionDispositionV2 {
    Available,
    RequiresExactApproval {
        reason: PermissionApprovalReasonV2,
    },
    Denied {
        reason: PermissionDeniedReasonV2,
    },
    Unavailable {
        reason: PermissionDispositionUnavailableReasonV2,
    },
}

/// One action's managed, preset, enforcement, and present admission facts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionActionProjectionV2 {
    pub managed_decision: PermissionManagedDecisionV2,
    pub preset_behavior: PermissionPresetBehaviorV2,
    pub enforcement_availability: PermissionEnforcementAvailabilityV2,
    pub disposition: PermissionDispositionV2,
}

/// A fixed six-key structure, so missing or unknown actions cannot be hidden.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionActionMapV2 {
    pub fs_read: PermissionActionProjectionV2,
    pub fs_create: PermissionActionProjectionV2,
    pub fs_write: PermissionActionProjectionV2,
    pub fs_delete: PermissionActionProjectionV2,
    pub process_start: PermissionActionProjectionV2,
    pub network_use: PermissionActionProjectionV2,
}

impl PermissionActionMapV2 {
    #[must_use]
    pub const fn get(&self, action: PermissionActionV2) -> &PermissionActionProjectionV2 {
        match action {
            PermissionActionV2::FsRead => &self.fs_read,
            PermissionActionV2::FsCreate => &self.fs_create,
            PermissionActionV2::FsWrite => &self.fs_write,
            PermissionActionV2::FsDelete => &self.fs_delete,
            PermissionActionV2::ProcessStart => &self.process_start,
            PermissionActionV2::NetworkUse => &self.network_use,
        }
    }

    pub(crate) fn iter(
        &self,
    ) -> impl Iterator<Item = (PermissionActionV2, &PermissionActionProjectionV2)> {
        [
            (PermissionActionV2::FsRead, &self.fs_read),
            (PermissionActionV2::FsCreate, &self.fs_create),
            (PermissionActionV2::FsWrite, &self.fs_write),
            (PermissionActionV2::FsDelete, &self.fs_delete),
            (PermissionActionV2::ProcessStart, &self.process_start),
            (PermissionActionV2::NetworkUse, &self.network_use),
        ]
        .into_iter()
    }
}
