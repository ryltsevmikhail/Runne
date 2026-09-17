use super::model::{nonzero, valid_time};
use super::root_service_messages::{
    RootArmRequest, RootIssuedProof, RootPrepareRequest, RootPrepared,
};
use super::{
    DesktopOffer, DesktopOfferRequest, MAX_QUALIFICATION_BOOTSTRAP_SIGNED_PROOF_BYTES,
    QualificationBootstrapControlError, RunBinding,
};

pub struct RuntimeBootstrapRequest {
    pub(super) offer_id: [u8; 32],
    pub(super) daemon_challenge: [u8; 32],
    pub(super) candidate_sha256: [u8; 32],
    pub(super) raw_v3_tuple_sha256: [u8; 32],
    pub(super) profile_sha256: [u8; 32],
}
impl RuntimeBootstrapRequest {
    pub fn new(
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        profile_sha256: [u8; 32],
    ) -> Result<Self, QualificationBootstrapControlError> {
        let value = Self {
            offer_id,
            daemon_challenge,
            candidate_sha256,
            raw_v3_tuple_sha256,
            profile_sha256,
        };
        [
            value.offer_id,
            value.daemon_challenge,
            value.candidate_sha256,
            value.raw_v3_tuple_sha256,
            value.profile_sha256,
        ]
        .iter()
        .all(nonzero)
        .then_some(value)
        .ok_or(QualificationBootstrapControlError::InvalidMessage)
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.offer_id
    }
    #[must_use]
    pub const fn daemon_challenge(&self) -> [u8; 32] {
        self.daemon_challenge
    }
    #[must_use]
    pub const fn candidate_sha256(&self) -> [u8; 32] {
        self.candidate_sha256
    }
    #[must_use]
    pub const fn raw_v3_tuple_sha256(&self) -> [u8; 32] {
        self.raw_v3_tuple_sha256
    }
    #[must_use]
    pub const fn profile_sha256(&self) -> [u8; 32] {
        self.profile_sha256
    }
}
pub struct RootConsumeRequest {
    pub(super) offer_id: [u8; 32],
    pub(super) daemon_challenge: [u8; 32],
    pub(super) signed_proof: Vec<u8>,
}
impl RootConsumeRequest {
    pub fn new(
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        signed_proof: Vec<u8>,
    ) -> Result<Self, QualificationBootstrapControlError> {
        let value = Self {
            offer_id,
            daemon_challenge,
            signed_proof,
        };
        (nonzero(&value.offer_id)
            && nonzero(&value.daemon_challenge)
            && !value.signed_proof.is_empty()
            && value.signed_proof.len() <= MAX_QUALIFICATION_BOOTSTRAP_SIGNED_PROOF_BYTES)
            .then_some(value)
            .ok_or(QualificationBootstrapControlError::InvalidMessage)
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.offer_id
    }
    #[must_use]
    pub const fn daemon_challenge(&self) -> [u8; 32] {
        self.daemon_challenge
    }
    #[must_use]
    pub fn signed_proof(&self) -> &[u8] {
        &self.signed_proof
    }
    #[must_use]
    pub fn into_signed_proof(self) -> Vec<u8> {
        self.signed_proof
    }
}
pub struct BootstrapAck {
    pub(super) offer_id: [u8; 32],
    pub(super) daemon_challenge: [u8; 32],
    pub(super) binding: RunBinding,
    pub(super) proof_sha256: [u8; 32],
    pub(super) run_not_after: u64,
}
impl BootstrapAck {
    pub fn new(
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        binding: RunBinding,
        proof_sha256: [u8; 32],
        run_not_after: u64,
    ) -> Result<Self, QualificationBootstrapControlError> {
        let value = Self {
            offer_id,
            daemon_challenge,
            binding,
            proof_sha256,
            run_not_after,
        };
        (nonzero(&value.offer_id)
            && nonzero(&value.daemon_challenge)
            && nonzero(&value.proof_sha256)
            && valid_time(value.run_not_after))
        .then_some(value)
        .ok_or(QualificationBootstrapControlError::InvalidMessage)
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.offer_id
    }
    #[must_use]
    pub const fn daemon_challenge(&self) -> [u8; 32] {
        self.daemon_challenge
    }
    #[must_use]
    pub const fn binding(&self) -> &RunBinding {
        &self.binding
    }
    #[must_use]
    pub const fn proof_sha256(&self) -> [u8; 32] {
        self.proof_sha256
    }
    #[must_use]
    pub const fn run_not_after(&self) -> u64 {
        self.run_not_after
    }
}

/// Only these unauthenticated bootstrap-control requests are accepted on the runner protocol.
pub enum BootstrapControlRequest {
    DesktopOffer(DesktopOfferRequest),
    RuntimeBootstrap(RuntimeBootstrapRequest),
    RootConsume(RootConsumeRequest),
    RootPrepare(RootPrepareRequest),
    RootArm(RootArmRequest),
}
/// Only these unauthenticated bootstrap-control replies are accepted on the runner protocol.
pub enum BootstrapControlReply {
    DesktopOffer(DesktopOffer),
    BootstrapAck(BootstrapAck),
    RootPrepared(RootPrepared),
    RootIssuedProof(RootIssuedProof),
}
impl BootstrapControlRequest {
    pub fn encode(&self) -> Result<Vec<u8>, QualificationBootstrapControlError> {
        super::request_wire::encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, QualificationBootstrapControlError> {
        super::request_wire::decode(bytes)
    }
}
impl BootstrapControlReply {
    pub fn encode(&self) -> Result<Vec<u8>, QualificationBootstrapControlError> {
        super::reply_wire::encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, QualificationBootstrapControlError> {
        super::reply_wire::decode(bytes)
    }
}
