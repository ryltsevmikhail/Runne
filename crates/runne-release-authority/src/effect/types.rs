#[cfg(any(test, feature = "fixture-only"))]
use crate::Digest;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectState {
    Planned,
    Claimed,
    InFlight,
    Succeeded,
    Uncertain,
    ReconciledSucceeded,
    ReconciledAbsent,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectSnapshot {
    pub state: EffectState,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectTransition {
    pub from: EffectSnapshot,
    pub to: EffectSnapshot,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EffectError {
    #[error("publication authorization binding is required")]
    MissingPublicationAuthorization,
    #[error("publication authorization binding does not exactly match the effect request")]
    AuthorizationBindingMismatch,
    #[error("publication authorization is expired or revoked")]
    AuthorizationExpiredOrRevoked,
    #[error("idempotency namespace was already planned")]
    DuplicateIdempotencyNamespace,
    #[error("idempotency namespace is bound to a divergent effect request")]
    DivergentIdempotencyNamespace,
    #[error("effect generation is stale")]
    StaleGeneration,
    #[error("invalid publication effect transition")]
    InvalidTransition,
    #[error("reconciliation attempt limit exceeded")]
    ReconciliationBoundExceeded,
}

/// Pure state-transition boundary. It cannot invoke an external effect.
pub trait PublicationEffectTransitionValidator {
    /// # Errors
    ///
    /// Returns an error unless the state and generation change is permitted.
    fn validate(&self, transition: EffectTransition) -> Result<(), EffectError>;
}

/// Production-safe validator; no backend, executor, or network capability exists here.
pub struct InertEffectTransitionValidator;

impl PublicationEffectTransitionValidator for InertEffectTransitionValidator {
    fn validate(&self, transition: EffectTransition) -> Result<(), EffectError> {
        use EffectState::{
            Blocked, Claimed, InFlight, Planned, ReconciledAbsent, ReconciledSucceeded, Succeeded,
            Uncertain,
        };
        let from = transition.from;
        let to = transition.to;
        let allowed = match (from.state, to.state) {
            (Planned, Claimed)
            | (Claimed, InFlight)
            | (InFlight, Succeeded | Uncertain)
            | (Uncertain, ReconciledSucceeded | ReconciledAbsent | Blocked) => {
                from.generation == to.generation
            }
            (ReconciledAbsent, Claimed) => from
                .generation
                .checked_add(1)
                .is_some_and(|generation| generation == to.generation),
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(EffectError::InvalidTransition)
        }
    }
}

#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationEffectRequest {
    promotion: String,
    revision: u64,
    manifest: Digest,
    destination: String,
    channel: String,
    executor: String,
    lane: String,
    workflow: Digest,
    idempotency_namespace: String,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
}

#[cfg(any(test, feature = "fixture-only"))]
pub struct EffectRequestFixture {
    pub promotion: String,
    pub revision: u64,
    pub manifest: Digest,
    pub destination: String,
    pub channel: String,
    pub executor: String,
    pub lane: String,
    pub workflow: Digest,
    pub idempotency_namespace: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
}

#[cfg(any(test, feature = "fixture-only"))]
impl PublicationEffectRequest {
    #[cfg(any(test, feature = "fixture-only"))]
    #[must_use]
    pub fn fixture(input: EffectRequestFixture) -> Self {
        Self {
            promotion: input.promotion,
            revision: input.revision,
            manifest: input.manifest,
            destination: input.destination,
            channel: input.channel,
            executor: input.executor,
            lane: input.lane,
            workflow: input.workflow,
            idempotency_namespace: input.idempotency_namespace,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            revocation_epoch: input.revocation_epoch,
        }
    }

    fn is_well_formed(&self) -> bool {
        self.valid_from < self.expires_at
            && matches!(self.channel.as_str(), "stable" | "beta" | "internal")
            && [
                &self.destination,
                &self.executor,
                &self.lane,
                &self.idempotency_namespace,
            ]
            .iter()
            .all(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
    }
}

#[cfg(any(test, feature = "fixture-only"))]
impl From<&PublicationEffectRequest> for EffectRequestFixture {
    fn from(value: &PublicationEffectRequest) -> Self {
        Self {
            promotion: value.promotion.clone(),
            revision: value.revision,
            manifest: value.manifest,
            destination: value.destination.clone(),
            channel: value.channel.clone(),
            executor: value.executor.clone(),
            lane: value.lane.clone(),
            workflow: value.workflow,
            idempotency_namespace: value.idempotency_namespace.clone(),
            valid_from: value.valid_from,
            expires_at: value.expires_at,
            revocation_epoch: value.revocation_epoch,
        }
    }
}

#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationAuthorizedBinding {
    request: PublicationEffectRequest,
    authorization: Digest,
}

#[cfg(any(test, feature = "fixture-only"))]
impl PublicationAuthorizedBinding {
    pub(crate) fn from_authorized_record(
        request: PublicationEffectRequest,
        authorization: Digest,
    ) -> Result<Self, EffectError> {
        if request.is_well_formed() {
            Ok(Self {
                request,
                authorization,
            })
        } else {
            Err(EffectError::AuthorizationBindingMismatch)
        }
    }
}

#[cfg(any(test, feature = "fixture-only"))]
impl PublicationAuthorizedBinding {
    pub(super) fn matches(&self, request: &PublicationEffectRequest) -> bool {
        self.request == *request
    }

    pub(super) const fn authorization(&self) -> Digest {
        self.authorization
    }

    /// Return the exact effect request authenticated by this opaque store-minted capability.
    #[must_use]
    pub const fn request(&self) -> &PublicationEffectRequest {
        &self.request
    }
}

#[cfg(any(test, feature = "fixture-only"))]
impl PublicationEffectRequest {
    pub(super) fn namespace(&self) -> &str {
        &self.idempotency_namespace
    }

    pub(super) const fn valid_from(&self) -> u64 {
        self.valid_from
    }

    pub(super) const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(super) const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    pub(crate) fn from_authorized_record(input: EffectRequestFixture) -> Result<Self, EffectError> {
        let request = Self::fixture(input);
        request
            .is_well_formed()
            .then_some(request)
            .ok_or(EffectError::AuthorizationBindingMismatch)
    }
}
