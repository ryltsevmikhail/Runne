use serde::{Deserialize, Serialize};

/// Closed preset values accepted by the shared runtime contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionModeV1 {
    AskAlways,
    RiskBased,
    FullAccess,
}

impl PermissionModeV1 {
    /// Stable numeric tag used by canonical command encoders.
    #[must_use]
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::AskAlways => 1,
            Self::RiskBased => 2,
            Self::FullAccess => 3,
        }
    }
}

/// Only the frozen initial preset generation is currently accepted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PermissionPresetVersionV1(u16);

impl PermissionPresetVersionV1 {
    /// Version 1 deterministic mode rules.
    pub const V1: Self = Self(1);

    /// Numeric version used by the application command contract.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Rejects unimplemented or zero preset versions.
    pub const fn from_u16(value: u16) -> Option<Self> {
        if value == 1 { Some(Self::V1) } else { None }
    }
}

/// Versioned containment reported by the current native owner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionContainmentV1 {
    WorkspaceBoundV1,
    SameUserCompositeV1,
}

/// Honest network posture exposed in current and historical projections.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionNetworkStateV1 {
    Unavailable,
    Brokered,
    BroadSameUser,
}

/// Closed reason that a selected mode currently has no effective admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionModeNotReadyReasonV1 {
    NativeContainment,
    CompositePolicyUnenforceable,
    PresetUnavailable,
}

/// Stable errors returned by the runtime-owned permission-mode port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionModeHostErrorV1 {
    NotFound,
    Conflict,
    IdempotencyConflict,
    StaleRevision,
    PolicyDenied,
    Expired,
    Cancelled,
    ReconciliationRequired,
    NativeAuthorityUnavailable,
    EnforcementUnavailable,
    CompositePolicyUnenforceable,
    UnsupportedPresetVersion,
    Unavailable,
    InvariantViolation,
}

impl PermissionModeHostErrorV1 {
    /// Stable transport-safe failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "permission_mode_not_found",
            Self::Conflict => "permission_mode_conflict",
            Self::IdempotencyConflict => "permission_mode_idempotency_conflict",
            Self::StaleRevision => "permission_mode_stale_revision",
            Self::PolicyDenied => "permission_mode_policy_denied",
            Self::Expired => "permission_mode_expired",
            Self::Cancelled => "permission_mode_cancelled",
            Self::ReconciliationRequired => "permission_mode_reconciliation_required",
            Self::NativeAuthorityUnavailable => "permission_mode_native_authority_unavailable",
            Self::EnforcementUnavailable => "permission_mode_enforcement_unavailable",
            Self::CompositePolicyUnenforceable => "permission_mode_scope_unenforceable",
            Self::UnsupportedPresetVersion => "permission_mode_preset_unsupported",
            Self::Unavailable => "permission_mode_unavailable",
            Self::InvariantViolation => "permission_mode_invariant_violation",
        }
    }
}
