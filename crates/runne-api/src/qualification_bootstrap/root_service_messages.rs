use super::messages::{RootConsumeRequest, RuntimeBootstrapRequest};
use super::model::{nonzero, valid_times};
use super::{QualificationBootstrapControlError, RunBinding};

/// Empty per-connection request; the broker supplies all qualification facts.
pub struct RootPrepareRequest;

impl RootPrepareRequest {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RootPrepareRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Root-service arm request uses the runtime-bootstrap digest validation.
pub type RootArmRequest = RuntimeBootstrapRequest;

pub struct RootPrepared {
    pub(super) offer_id: [u8; 32],
    pub(super) binding: RunBinding,
    pub(super) expires_at: u64,
    pub(super) run_not_after: u64,
}

impl RootPrepared {
    pub fn new(
        offer_id: [u8; 32],
        binding: RunBinding,
        expires_at: u64,
        run_not_after: u64,
    ) -> Result<Self, QualificationBootstrapControlError> {
        let value = Self {
            offer_id,
            binding,
            expires_at,
            run_not_after,
        };
        (nonzero(&value.offer_id) && valid_times(value.expires_at, value.run_not_after))
            .then_some(value)
            .ok_or(QualificationBootstrapControlError::InvalidMessage)
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.offer_id
    }
    #[must_use]
    pub const fn binding(&self) -> &RunBinding {
        &self.binding
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn run_not_after(&self) -> u64 {
        self.run_not_after
    }
}

/// Bounded root-service proof; intentionally does not implement `Debug`.
pub struct RootIssuedProof(RootConsumeRequest);

impl RootIssuedProof {
    pub fn new(
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        signed_proof: Vec<u8>,
    ) -> Result<Self, QualificationBootstrapControlError> {
        RootConsumeRequest::new(offer_id, daemon_challenge, signed_proof).map(Self)
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.0.offer_id()
    }
    #[must_use]
    pub const fn daemon_challenge(&self) -> [u8; 32] {
        self.0.daemon_challenge()
    }
    #[must_use]
    pub fn signed_proof(&self) -> &[u8] {
        self.0.signed_proof()
    }
    #[must_use]
    pub fn into_signed_proof(self) -> Vec<u8> {
        self.0.into_signed_proof()
    }
}
