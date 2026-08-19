#![allow(clippy::missing_errors_doc)] // Fixture handles expose fallible, fail-closed transitions.
use crate::Digest;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rc2SigningEffectLeaseState {
    Planned,
    Claimed,
    InFlight,
    Completed,
    Uncertain,
    Blocked,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EffectLeaseError {
    #[error("signing authorization is malformed")]
    InvalidAuthorization,
    #[error("signing authorization is expired or revoked")]
    AuthorizationExpiredOrRevoked,
    #[error("an exact signing claim already exists")]
    DuplicateClaim,
    #[error("the signing namespace is bound to divergent claims")]
    DivergentClaim,
    #[error("the signing namespace is already claimed by another promotion")]
    NamespaceAlreadyClaimed,
    #[error("effect generation is stale")]
    StaleGeneration,
    #[error("effect lease is not dispatchable")]
    InvalidLeaseState,
    #[error("opaque backend readback does not bind this claim")]
    ReadbackMismatch,
    #[error("durable signing-effect ledger is unavailable or corrupt")]
    DurableStateUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rc2SigningAuthorizationFixture {
    pub authority_instance: Digest,
    pub promotion: String,
    pub revision: u64,
    pub authorization: Digest,
    pub namespace: String,
    pub generation: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub workflow: Digest,
    pub signer: String,
    pub runner: String,
    pub slots: [(String, Digest, u64); 3],
}

impl Rc2SigningAuthorizationFixture {
    pub fn signing_authorized(self) -> Result<FixtureRc2SigningAuthorization, EffectLeaseError> {
        valid(&self)
            .then_some(FixtureRc2SigningAuthorization(self))
            .ok_or(EffectLeaseError::InvalidAuthorization)
    }
}

impl From<&FixtureRc2SigningAuthorization> for Rc2SigningAuthorizationFixture {
    fn from(value: &FixtureRc2SigningAuthorization) -> Self {
        value.0.clone()
    }
}

/// Opaque fixture representation of an RC2 stage that has reached `SigningAuthorized`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureRc2SigningAuthorization(pub(super) Rc2SigningAuthorizationFixture);

impl FixtureRc2SigningAuthorization {
    pub(crate) fn fixture(&self) -> Rc2SigningAuthorizationFixture {
        self.0.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rc2SigningEffectClaim {
    pub slot: String,
    pub state: Rc2SigningEffectLeaseState,
    pub generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Rc2SigningDispatchLease {
    pub(super) authority_instance: Digest,
    pub(super) namespace: String,
    pub(super) authorization: Digest,
    pub(super) generation: u64,
    pub(super) slot: String,
}

/// Move-only dispatch lease minted only by the ledger reservation.
#[derive(Debug, Eq, PartialEq)]
pub struct FixtureRc2SigningDispatchLease(pub(super) Rc2SigningDispatchLease);

impl FixtureRc2SigningDispatchLease {
    #[must_use]
    pub const fn state(&self) -> Rc2SigningEffectLeaseState {
        Rc2SigningEffectLeaseState::InFlight
    }
    pub(crate) fn slot(&self) -> &str {
        &self.0.slot
    }
    pub(crate) fn namespace(&self) -> &str {
        &self.0.namespace
    }
    pub(crate) const fn authority_instance(&self) -> Digest {
        self.0.authority_instance
    }
    pub(crate) const fn authorization(&self) -> Digest {
        self.0.authorization
    }
    pub(crate) const fn generation(&self) -> u64 {
        self.0.generation
    }
}

/// Exactly three move-only slot leases minted together from one RC2 authorization reservation.
#[derive(Debug, Eq, PartialEq)]
pub struct FixtureRc2SigningDispatchLeases(pub(super) [Option<FixtureRc2SigningDispatchLease>; 3]);

impl FixtureRc2SigningDispatchLeases {
    pub fn take(&mut self, slot: &str) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        self.0
            .iter_mut()
            .find(|lease| lease.as_ref().is_some_and(|lease| lease.0.slot == slot))
            .and_then(Option::take)
            .ok_or(EffectLeaseError::InvalidLeaseState)
    }
}

/// Store-internal move-only proof that one exact completed effect ledger may close one bundle.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FixtureRc2EffectClosure {
    pub(crate) authority_instance: Digest,
    pub(crate) promotion: String,
    pub(crate) namespace: String,
    pub(crate) generation: u64,
    pub(crate) authorization: Digest,
    pub(crate) commitment: Digest,
    pub(crate) ledger_identity: Digest,
}

pub struct Rc2SigningBackendReadbackFixture {
    pub(super) slot: String,
    pub(super) artifact: String,
    pub(super) runner: String,
    pub(super) outcome: Rc2SigningEffectLeaseState,
}

impl Rc2SigningBackendReadbackFixture {
    pub(crate) fn verified(
        slot: String,
        artifact: String,
        runner: String,
        outcome: &str,
    ) -> Result<Self, EffectLeaseError> {
        Ok(Self {
            slot,
            artifact,
            runner,
            outcome: match outcome {
                "succeeded" => Rc2SigningEffectLeaseState::Completed,
                "absent" => Rc2SigningEffectLeaseState::Blocked,
                "inconclusive" => Rc2SigningEffectLeaseState::Uncertain,
                _ => return Err(EffectLeaseError::ReadbackMismatch),
            },
        })
    }
}

pub(super) fn valid(input: &Rc2SigningAuthorizationFixture) -> bool {
    input.revision > 0
        && input.generation > 0
        && input.valid_from < input.expires_at
        && input.revocation_epoch > 0
        && [
            &input.promotion,
            &input.namespace,
            &input.signer,
            &input.runner,
        ]
        .into_iter()
        .all(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
        && input.signer != input.runner
        && input
            .slots
            .iter()
            .all(|(slot, _, length)| !slot.is_empty() && *length > 0)
        && input
            .slots
            .iter()
            .enumerate()
            .all(|(index, slot)| input.slots[..index].iter().all(|prior| prior.0 != slot.0))
}
