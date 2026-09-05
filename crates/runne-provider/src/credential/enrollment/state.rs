use std::sync::Arc;

use thiserror::Error;

use super::{CredentialBindingDigest, CredentialFence, authority::EnrollmentAuthoritySeal};

/// Closed failure vocabulary for enrollment-domain validation and broker frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CredentialEnrollmentError {
    /// Input violates an exact type or bounded codec invariant.
    #[error("credential enrollment input is invalid")]
    InvalidInput,
    /// The operating-system entropy source did not return a nonce.
    #[error("credential enrollment entropy is unavailable")]
    EntropyUnavailable,
    /// The state graph does not permit this transition.
    #[error("credential enrollment transition is invalid")]
    InvalidTransition,
    /// Required evidence does not close the transition safely.
    #[error("credential enrollment evidence is invalid")]
    InvalidEvidence,
    /// The broker frame is unknown, malformed, or exceeds its bound.
    #[error("credential enrollment broker frame is invalid")]
    InvalidFrame,
}

/// Closed durable operation action vocabulary.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialOperationAction {
    /// Protected user-authorized creation or rotation.
    Pair = 1,
    /// Provider fence followed by native removal.
    Revoke = 2,
    /// One-time legacy-source import.
    MigrateLegacy = 3,
    /// Daemon-created retired native-version cleanup.
    RetiredVersionCleanup = 4,
    /// Daemon-created legacy source cleanup.
    LegacySourceCleanup = 5,
    /// Old release writer effect during identity migration.
    WriterIdentityMigrationEffect = 6,
    /// New release writer verification during identity migration.
    WriterIdentityMigrationVerify = 7,
}

/// Closed durable enrollment state vocabulary.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialOperationState {
    /// Durable operation is awaiting a ticket claim.
    Prepared = 1,
    /// The exact ticket and live writer process were atomically admitted.
    Claimed = 2,
    /// Native mutation may have occurred and must be reconciled.
    NativeEffectObserved = 3,
    /// Independent metadata-only native readback was recorded.
    ReadbackVerified = 4,
    /// Lifecycle CAS completed authoritatively.
    Completed = 5,
    /// Exact absence proves a create/import did not mutate native state.
    Failed = 6,
    /// Pre-claim ticket lifetime elapsed.
    Expired = 7,
    /// Pre-claim user cancellation completed.
    Cancelled = 8,
    /// Retention/cleanup permanently closed replay and ABA.
    Tombstoned = 9,
}

impl CredentialOperationState {
    /// Every state, for exhaustive transition validation.
    pub const ALL: [Self; 9] = [
        Self::Prepared,
        Self::Claimed,
        Self::NativeEffectObserved,
        Self::ReadbackVerified,
        Self::Completed,
        Self::Failed,
        Self::Expired,
        Self::Cancelled,
        Self::Tombstoned,
    ];
}

/// Evidence that a durable store transaction independently recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialTransitionEvidence {
    /// No post-claim native/effect evidence exists.
    None,
    /// Independent readback proves exact native absence.
    ExactAbsenceReadback(CredentialBindingDigest),
    /// Independent readback proves the exact immutable version.
    ExactVersionReadback(CredentialBindingDigest),
    /// The revoke dispatch fence committed before cleanup/reconciliation.
    RevokeFenceCommitted(CredentialFence),
}

/// Store-constructed and validated transition request.
pub struct TransitionCommand {
    seal: Arc<EnrollmentAuthoritySeal>,
    action: CredentialOperationAction,
    from: CredentialOperationState,
    to: CredentialOperationState,
    evidence: CredentialTransitionEvidence,
}

impl TransitionCommand {
    /// Validates the structural graph and evidence-aware post-claim guard.
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        action: CredentialOperationAction,
        from: CredentialOperationState,
        to: CredentialOperationState,
        evidence: CredentialTransitionEvidence,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !allows_structural_transition(from, to) {
            return Err(CredentialEnrollmentError::InvalidTransition);
        }
        if !allows_evidence(action, from, to, evidence) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(Self {
            seal,
            action,
            from,
            to,
            evidence,
        })
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }

    /// Returns the closed operation action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }

    /// Returns the authoritative prior state.
    pub const fn from(&self) -> CredentialOperationState {
        self.from
    }

    /// Returns the validated successor state.
    pub const fn to(&self) -> CredentialOperationState {
        self.to
    }

    /// Returns the independently recorded transition evidence.
    pub const fn evidence(&self) -> CredentialTransitionEvidence {
        self.evidence
    }
}

/// Reports whether the closed structural graph contains this edge.
pub const fn allows_structural_transition(
    from: CredentialOperationState,
    to: CredentialOperationState,
) -> bool {
    use CredentialOperationState as S;
    matches!(
        (from, to),
        (
            S::Prepared,
            S::Claimed | S::Failed | S::Expired | S::Cancelled
        ) | (S::Claimed, S::NativeEffectObserved | S::Failed)
            | (S::NativeEffectObserved, S::ReadbackVerified | S::Failed)
            | (S::ReadbackVerified, S::Completed)
            | (
                S::Completed | S::Failed | S::Expired | S::Cancelled,
                S::Tombstoned
            )
    )
}

fn allows_evidence(
    action: CredentialOperationAction,
    from: CredentialOperationState,
    to: CredentialOperationState,
    evidence: CredentialTransitionEvidence,
) -> bool {
    match (from, to) {
        (
            CredentialOperationState::Prepared,
            CredentialOperationState::Failed
            | CredentialOperationState::Expired
            | CredentialOperationState::Cancelled,
        ) if action == CredentialOperationAction::Revoke => false,
        (CredentialOperationState::Claimed, CredentialOperationState::Failed)
        | (CredentialOperationState::NativeEffectObserved, CredentialOperationState::Failed) => {
            matches!(
                action,
                CredentialOperationAction::Pair
                    | CredentialOperationAction::MigrateLegacy
                    | CredentialOperationAction::RetiredVersionCleanup
            ) && matches!(
                evidence,
                CredentialTransitionEvidence::ExactAbsenceReadback(_)
            )
        }
        (CredentialOperationState::Claimed, CredentialOperationState::NativeEffectObserved)
            if matches!(action, CredentialOperationAction::Revoke) =>
        {
            matches!(
                evidence,
                CredentialTransitionEvidence::RevokeFenceCommitted(_)
            )
        }
        (
            CredentialOperationState::NativeEffectObserved,
            CredentialOperationState::ReadbackVerified,
        )
        | (CredentialOperationState::ReadbackVerified, CredentialOperationState::Completed) => {
            action_accepts_readback(action, evidence)
        }
        _ => matches!(evidence, CredentialTransitionEvidence::None),
    }
}

fn action_accepts_readback(
    action: CredentialOperationAction,
    evidence: CredentialTransitionEvidence,
) -> bool {
    match action {
        CredentialOperationAction::Pair
        | CredentialOperationAction::MigrateLegacy
        | CredentialOperationAction::WriterIdentityMigrationVerify => matches!(
            evidence,
            CredentialTransitionEvidence::ExactVersionReadback(_)
        ),
        CredentialOperationAction::Revoke
        | CredentialOperationAction::RetiredVersionCleanup
        | CredentialOperationAction::LegacySourceCleanup => matches!(
            evidence,
            CredentialTransitionEvidence::ExactAbsenceReadback(_)
        ),
        CredentialOperationAction::WriterIdentityMigrationEffect => false,
    }
}

/// Safe public disposition for broker admission/availability outcomes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialDisposition {
    /// Identity or authority binding was rejected.
    AccessDenied = 1,
    /// The requested protected capability is not implemented on this platform.
    Unsupported = 2,
    /// A bound dependency or channel is unavailable.
    Unavailable = 3,
    /// Durable compare-and-set state conflicted.
    Conflict = 4,
}

impl CredentialDisposition {
    #[allow(dead_code)]
    pub(crate) const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::AccessDenied),
            2 => Some(Self::Unsupported),
            3 => Some(Self::Unavailable),
            4 => Some(Self::Conflict),
            _ => None,
        }
    }
}
