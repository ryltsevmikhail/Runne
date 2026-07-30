use thiserror::Error;

use gocode_provider::DispatchAttemptId;

/// Revision-bound reference to durable provider-effect authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderEffectAuthorityRef {
    authority_id: [u8; 16],
    revision: u64,
}

impl ProviderEffectAuthorityRef {
    /// Creates a non-zero, positive-revision authority reference.
    pub fn new(authority_id: [u8; 16], revision: u64) -> Result<Self, ProviderAdmissionError> {
        if authority_id == [0; 16] || revision == 0 {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        Ok(Self {
            authority_id,
            revision,
        })
    }

    /// Returns the durable authority identity.
    pub const fn authority_id(self) -> [u8; 16] {
        self.authority_id
    }

    /// Returns the authority revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }
}

/// Authoritative, revision-bound provider-effect authorization record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEffectAuthorityRecord {
    /// Immutable authority identity and revision.
    pub authority_ref: ProviderEffectAuthorityRef,
    /// Bound durable dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Bound winner-only permit.
    pub permit_id: [u8; 16],
    /// Granted capability retained by the authority issuer.
    pub capability_grant_id: String,
    /// Bound token reservation.
    pub token_reservation_id: [u8; 16],
    /// Bound cost reservation.
    pub cost_reservation_id: [u8; 16],
    /// Bound prepared request digest.
    pub prepared_digest: [u8; 32],
    /// Bound render digest.
    pub render_digest: [u8; 32],
    /// Bound provider profile digest.
    pub profile_digest: [u8; 32],
    /// Authority owner identity.
    pub owner_id: String,
    /// Authority scope.
    pub scope: String,
    /// Bound non-zero fencing token.
    pub fencing_token: u64,
    /// Inclusive Unix timestamp after which the authority is denied.
    pub expires_at: i64,
    /// Whether an issuer revoked the authority.
    pub revoked: bool,
    /// Whether admission has consumed the authority.
    pub consumed: bool,
}

/// Exact provider effect admission input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEffectRequest {
    /// Reference to issuer-created, revision-bound authority.
    pub authority_ref: ProviderEffectAuthorityRef,
    /// Durable dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Winner-only permit.
    pub permit_id: [u8; 16],
    /// Exact prepared request digest.
    pub prepared_digest: [u8; 32],
    /// Exact committed render digest.
    pub render_digest: [u8; 32],
    /// Exact provider profile digest.
    pub profile_digest: [u8; 32],
    /// Token budget reservation.
    pub token_reservation_id: [u8; 16],
    /// Cost budget reservation.
    pub cost_reservation_id: [u8; 16],
    /// Current fencing token.
    pub fencing_token: u64,
    /// Caller identity reference, verified against issued authority.
    pub owner_id: String,
    /// Requested authority scope reference, verified against issued authority.
    pub scope: String,
}

/// Typed rejection before adapter network code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderAdmissionError {
    /// Prohibited content or unavailable policy classification denied delivery.
    #[error("provider request was denied by content policy")]
    PolicyDenied,
    /// Issued provider-effect authority is absent, invalid, expired, revoked, or consumed.
    #[error("provider effect authority was denied")]
    AuthorityDenied,
    /// A caller binding conflicts with its issued authority or existing admission.
    #[error("provider effect authority conflicts with the requested effect")]
    AuthorityConflict,
    /// Capability or approval authority is absent.
    #[error("provider capability was denied")]
    CapabilityDenied,
    /// Token reservation does not bind this effect.
    #[error("provider token reservation mismatch")]
    TokenReservationMismatch,
    /// Cost reservation does not bind this effect.
    #[error("provider cost reservation mismatch")]
    CostReservationMismatch,
    /// Render evidence differs from the prepared request.
    #[error("provider render digest mismatch")]
    RenderDigestMismatch,
    /// Permit does not bind this effect.
    #[error("provider permit mismatch")]
    PermitMismatch,
    /// Worker generation no longer owns the effect.
    #[error("provider fencing token is stale")]
    StaleFencingToken,
    /// Atomic admission may have committed but acknowledgement was lost.
    #[error("provider effect admission is uncertain")]
    PostClaimUncertain,
    /// Prepare failed before dispatch.
    #[error("provider request preparation failed")]
    PrepareRejected,
    /// Durable repository failed closed.
    #[error("provider repository failed")]
    RepositoryFailure,
}

/// Atomic audit/budget/intent/permit admission port.
pub trait ProviderEffectAdmission: Send + Sync {
    /// Commits the full pre-effect boundary or returns typed rejection.
    fn admit(&self, request: &ProviderEffectRequest) -> Result<(), ProviderAdmissionError>;
}
