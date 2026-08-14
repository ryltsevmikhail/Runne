//! Exact immutable scope and state machine for the candidate-global publication effect.

#![allow(clippy::missing_errors_doc, dead_code, clippy::redundant_pub_crate)] // Incremental fixture reference.

use crate::Digest;
use thiserror::Error;

/// Terminal and intermediate states of one publication effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationEffectState {
    Authorized,
    Claimed,
    InFlight,
    Succeeded,
    Uncertain,
    ReconciledSucceeded,
    ReconciledAbsent,
    Blocked,
}

/// Fail-closed publication-effect errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PublicationEffectError {
    #[error("publication authorization is malformed")]
    InvalidAuthorization,
    #[error("publication owner policy proof is unresolved")]
    PolicyUnresolved,
    #[error("publication authorization is expired or revoked")]
    AuthorizationExpiredOrRevoked,
    #[error("an exact publication claim already exists")]
    DuplicateClaim,
    #[error("the publication namespace is bound to a divergent claim")]
    DivergentClaim,
    #[error("publication effect command replay fingerprint diverged")]
    CommandReplayDiverged,
    #[error("the publication namespace is claimed by another promotion")]
    NamespaceAlreadyClaimed,
    #[error("publication effect generation is stale")]
    StaleGeneration,
    #[error("publication effect is not in a dispatchable state")]
    InvalidState,
    #[error("settlement/readback does not bind this claim")]
    SettlementMismatch,
    #[error("reconciliation attempt limit exceeded")]
    ReconciliationBoundExceeded,
    #[error("durable publication-effect ledger is unavailable or corrupt")]
    DurableStateUnavailable,
}

/// Exact immutable scope of one publication effect, bound before any mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationEffectScope {
    pub authority_instance: Digest,
    pub promotion: String,
    pub candidate_digest: Digest,
    pub rc3_authorization_digest: Digest,
    pub manifest_digest: Digest,
    pub final_review_digest: Digest,
    pub allowlist_digest: Digest,
    pub allowlist_generation: u64,
    pub destination: String,
    pub channel: String,
    pub effect_kind: String,
    pub effect_scope_digest: Digest,
    pub executor: [String; 5],
    pub executable_digest: Digest,
    pub workflow_digest: Digest,
    pub idempotency_namespace: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub generation: u64,
}

impl PublicationEffectScope {
    pub(crate) fn is_well_formed(&self) -> bool {
        self.generation > 0
            && self.allowlist_generation > 0
            && self.valid_from < self.expires_at
            && self.revocation_epoch > 0
            && [
                &self.promotion,
                &self.destination,
                &self.channel,
                &self.effect_kind,
                &self.idempotency_namespace,
            ]
            .into_iter()
            .all(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
            && self
                .executor
                .iter()
                .all(|id| !id.is_empty() && !id.chars().any(char::is_whitespace))
    }
}

/// Store-internal move-only dispatch lease minted only by the ledger claim.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PublicationDispatchLease {
    pub(crate) authority_instance: Digest,
    pub(crate) idempotency_namespace: String,
    pub(crate) generation: u64,
    pub(crate) capability: Digest,
}

/// Move-only publication dispatch capability. No `Clone`, no public constructor.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FixturePublicationDispatch(pub(super) PublicationDispatchLease);

impl FixturePublicationDispatch {
    pub(crate) const fn authority_instance(&self) -> Digest {
        self.0.authority_instance
    }
    pub(crate) fn namespace(&self) -> &str {
        &self.0.idempotency_namespace
    }
    pub(crate) const fn generation(&self) -> u64 {
        self.0.generation
    }
    pub(crate) const fn capability(&self) -> Digest {
        self.0.capability
    }
}

/// Stable durable outcome returned for an exact response-loss replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationEffectReplay {
    pub(crate) command_fingerprint: Digest,
    pub(crate) state: PublicationEffectState,
    pub(crate) generation: u64,
    pub(crate) evidence: Option<Digest>,
}

/// Read-only recovery snapshot. It is not accepted by any effect transition API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationEffectRecovery {
    pub(crate) state: PublicationEffectState,
    pub(crate) generation: u64,
    pub(crate) settlement: Option<Digest>,
}

/// First execution carries the only live move-only capability; replay never does.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PublicationEffectExecution {
    Applied(FixturePublicationDispatch),
    Replayed(PublicationEffectReplay),
}

impl PublicationEffectExecution {
    pub(crate) fn applied(self) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        match self {
            Self::Applied(capability) => Ok(capability),
            Self::Replayed(_) => Err(PublicationEffectError::InvalidState),
        }
    }
}

/// Authenticated readback outcome for reconciliation of an uncertain effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReconcileOutcome {
    Succeeded,
    Absent,
    Inconclusive,
}

/// Permitted state transitions. `ReconciledAbsent` re-opens a claim at generation + 1.
#[allow(clippy::unnested_or_patterns, clippy::missing_const_for_fn)]
pub(crate) fn allowed(from: PublicationEffectState, to: PublicationEffectState) -> bool {
    use PublicationEffectState::{
        Authorized, Blocked, Claimed, InFlight, ReconciledAbsent, ReconciledSucceeded, Succeeded,
        Uncertain,
    };
    matches!(
        (from, to),
        (Authorized, Claimed)
            | (Claimed, InFlight)
            | (InFlight, Succeeded | Uncertain)
            | (Uncertain, ReconciledSucceeded | ReconciledAbsent | Blocked)
            | (ReconciledAbsent, Claimed)
    )
}
