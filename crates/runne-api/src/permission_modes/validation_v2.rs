mod actions;
mod full_access;
mod scopes;

use super::{
    PermissionContainmentV2, PermissionEffectiveStateV2, PermissionModeHistoryV2,
    PermissionModeLifecycleV2, PermissionModeNotReadyReasonV2, PermissionModeStatusV2,
    PermissionNetworkStateV2, PermissionPresetVersionV1,
};

/// Stable validation categories for untrusted V2 projection data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionModeValidationErrorV2 {
    RevisionOutOfRange,
    InvalidExpiry,
    ZeroObservationGeneration,
    ZeroScopeDigest,
    EffectiveModeMismatch,
    EffectivePresetMismatch,
    EffectiveContainmentMismatch,
    NetworkMismatch,
    LifecycleMismatch,
    InvalidActionMap,
    InvalidScopes,
    InvalidFullAccessProjection,
    InvalidReceipt,
}

impl PermissionModeStatusV2 {
    /// Validates the status fields and their cross-field projection invariants.
    pub fn validate(&self) -> Result<(), PermissionModeValidationErrorV2> {
        validate_projection(
            ProjectionFacts {
                selected_mode: self.selected_mode,
                preset_version: self.preset_version,
                containment: self.containment,
                network_state: self.network_state,
                observation_generation: self.observation_generation,
                expires_at_unix_ms: self.expires_at_unix_ms,
                authorization_revision: self.authorization_revision,
                lifecycle: self.lifecycle,
            },
            &self.effective,
        )
    }
}

impl PermissionModeHistoryV2 {
    /// Validates capture-time facts without re-evaluating current authority or expiry.
    pub fn validate(&self) -> Result<(), PermissionModeValidationErrorV2> {
        validate_projection(
            ProjectionFacts {
                selected_mode: self.selected_mode,
                preset_version: self.preset_version,
                containment: self.containment,
                network_state: self.network_state,
                observation_generation: self.observation_generation,
                expires_at_unix_ms: self.expires_at_unix_ms,
                authorization_revision: self.authorization_revision,
                lifecycle: self.lifecycle,
            },
            &self.effective,
        )
    }
}

impl super::PermissionModeChangeReceiptV2 {
    /// Validates receipt identity links and its immutable captured history.
    pub fn validate(&self) -> Result<(), PermissionModeValidationErrorV2> {
        self.history.validate()?;
        if self.authorization_revision != self.history.authorization_revision
            || self.selected_mode != self.history.selected_mode
            || self.idempotency_key.is_empty()
        {
            return Err(PermissionModeValidationErrorV2::InvalidReceipt);
        }
        Ok(())
    }
}

impl super::PermissionModeCommandStatusV3 {
    /// Validates fields whose meaning was introduced by the V3 envelope.
    pub fn validate(&self) -> Result<(), PermissionModeValidationErrorV2> {
        match self {
            Self::PendingNativeConfirmation {
                expires_at_unix_ms, ..
            }
            | Self::PendingReauthentication {
                expires_at_unix_ms, ..
            } if *expires_at_unix_ms <= 0 => Err(PermissionModeValidationErrorV2::InvalidExpiry),
            Self::Committed { receipt } => match receipt.as_ref() {
                super::PermissionModeChangeReceiptV3::V2 { receipt } => receipt.validate(),
                super::PermissionModeChangeReceiptV3::V1 { .. } => Ok(()),
            },
            _ => Ok(()),
        }
    }
}

struct ProjectionFacts {
    selected_mode: super::PermissionModeV1,
    preset_version: PermissionPresetVersionV1,
    containment: Option<PermissionContainmentV2>,
    network_state: PermissionNetworkStateV2,
    observation_generation: u64,
    expires_at_unix_ms: Option<i64>,
    authorization_revision: u64,
    lifecycle: PermissionModeLifecycleV2,
}

fn validate_projection(
    facts: ProjectionFacts,
    effective: &PermissionEffectiveStateV2,
) -> Result<(), PermissionModeValidationErrorV2> {
    if facts.authorization_revision > i64::MAX as u64 {
        return Err(PermissionModeValidationErrorV2::RevisionOutOfRange);
    }
    if facts.expires_at_unix_ms.is_some_and(|expiry| expiry <= 0) {
        return Err(PermissionModeValidationErrorV2::InvalidExpiry);
    }
    if facts.observation_generation == 0 {
        return Err(PermissionModeValidationErrorV2::ZeroObservationGeneration);
    }

    let scopes = effective.scopes();
    let action_map = effective.action_map();
    validate_preset_behaviors(facts.selected_mode, action_map)?;
    if facts.network_state != scopes.network {
        return Err(PermissionModeValidationErrorV2::NetworkMismatch);
    }
    scopes::validate(scopes, action_map)?;
    actions::validate(action_map, facts.lifecycle)?;

    match effective {
        PermissionEffectiveStateV2::Ready {
            mode,
            preset_version: effective_preset,
            scope_digest,
            containment: effective_containment,
            action_map,
            scopes,
        } => {
            if facts.lifecycle != PermissionModeLifecycleV2::Current {
                return Err(PermissionModeValidationErrorV2::LifecycleMismatch);
            }
            if *mode != facts.selected_mode {
                return Err(PermissionModeValidationErrorV2::EffectiveModeMismatch);
            }
            if *effective_preset != facts.preset_version {
                return Err(PermissionModeValidationErrorV2::EffectivePresetMismatch);
            }
            if facts.containment != Some(*effective_containment) {
                return Err(PermissionModeValidationErrorV2::EffectiveContainmentMismatch);
            }
            if scope_digest.as_bytes().iter().all(|byte| *byte == 0) {
                return Err(PermissionModeValidationErrorV2::ZeroScopeDigest);
            }
            if matches!(scopes.network, PermissionNetworkStateV2::BroadSameUser)
                && !matches!(
                    effective_containment,
                    PermissionContainmentV2::SameUserCompositeV1
                        | PermissionContainmentV2::SameUserCompositeV2
                )
            {
                return Err(PermissionModeValidationErrorV2::EffectiveContainmentMismatch);
            }
            if facts.selected_mode == super::PermissionModeV1::FullAccess {
                full_access::validate(*effective_containment, action_map, scopes)?;
            }
        }
        PermissionEffectiveStateV2::NotReady { reason, .. } => {
            validate_lifecycle_reason(facts.lifecycle, *reason)?;
        }
    }
    Ok(())
}

fn validate_preset_behaviors(
    mode: super::PermissionModeV1,
    action_map: &super::PermissionActionMapV2,
) -> Result<(), PermissionModeValidationErrorV2> {
    use super::{
        PermissionActionV2, PermissionModeV1 as Mode, PermissionPresetBehaviorV2 as Behavior,
    };

    for (action, projection) in action_map.iter() {
        let expected = match mode {
            Mode::AskAlways if action == PermissionActionV2::FsRead => {
                Behavior::PerEffectEvaluation
            }
            Mode::AskAlways => Behavior::ExactApprovalRequired,
            Mode::RiskBased => Behavior::PerEffectEvaluation,
            Mode::FullAccess => Behavior::NoPresetPrompt,
        };
        if projection.preset_behavior != expected {
            return Err(PermissionModeValidationErrorV2::InvalidActionMap);
        }
    }
    Ok(())
}

fn validate_lifecycle_reason(
    lifecycle: PermissionModeLifecycleV2,
    reason: PermissionModeNotReadyReasonV2,
) -> Result<(), PermissionModeValidationErrorV2> {
    let matches = match lifecycle {
        PermissionModeLifecycleV2::Current => !matches!(
            reason,
            PermissionModeNotReadyReasonV2::StaleObservation
                | PermissionModeNotReadyReasonV2::Revoked
                | PermissionModeNotReadyReasonV2::Reconciling
        ),
        PermissionModeLifecycleV2::Stale => {
            reason == PermissionModeNotReadyReasonV2::StaleObservation
        }
        PermissionModeLifecycleV2::Revoked => reason == PermissionModeNotReadyReasonV2::Revoked,
        PermissionModeLifecycleV2::Reconciling => {
            reason == PermissionModeNotReadyReasonV2::Reconciling
        }
    };
    if matches {
        Ok(())
    } else {
        Err(PermissionModeValidationErrorV2::LifecycleMismatch)
    }
}
