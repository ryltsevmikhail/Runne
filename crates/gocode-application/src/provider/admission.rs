use thiserror::Error;

/// Revision-bound reference to durable provider-effect authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderEffectAuthorityRef {
    authority_id: [u8; 16],
    revision: u64,
}

/// Closed activation identity required for a runtime-owned provider lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLeaseBindingKind {
    /// Protected protocol V2 session.
    ProtectedV2,
    /// Fixed owner-private external configuration.
    ExternalOwnerPrivate,
}

impl ProviderLeaseBindingKind {
    /// Durable closed code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProtectedV2 => "protected_v2",
            Self::ExternalOwnerPrivate => "external_owner_private",
        }
    }
}

/// Non-secret aggregate budget state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderBudgetUtilization {
    pub limit: u64,
    pub reserved: u64,
    pub settled: u64,
    pub remaining: u64,
}

impl ProviderBudgetUtilization {
    /// Validates and derives remaining capacity.
    pub fn new(limit: u64, reserved: u64, settled: u64) -> Result<Self, ProviderAdmissionError> {
        let remaining = limit
            .checked_sub(reserved)
            .and_then(|value| value.checked_sub(settled))
            .ok_or(ProviderAdmissionError::RepositoryFailure)?;
        Ok(Self {
            limit,
            reserved,
            settled,
            remaining,
        })
    }
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
    /// Required capability lease expired.
    #[error("provider capability expired")]
    CapabilityExpired,
    /// Required human or policy approval is absent.
    #[error("provider approval was denied")]
    ApprovalDenied,
    /// Required approval existed but expired before atomic admission.
    #[error("provider approval expired")]
    ApprovalExpired,
    /// Required capability is invalidated by a revocation epoch.
    #[error("provider capability was revoked")]
    CapabilityRevoked,
    /// Required approval is invalidated by a revocation epoch.
    #[error("provider approval was revoked")]
    ApprovalRevoked,
    /// Requested token reservation exceeds the current durable budget.
    #[error("provider token budget was denied")]
    TokenBudgetDenied,
    /// Requested worst-case cost exceeds the current durable budget.
    #[error("provider cost budget was denied")]
    CostBudgetDenied,
    /// Runtime pricing revision differs from the requested immutable profile.
    #[error("provider pricing revision mismatch")]
    PricingRevisionMismatch,
    /// Semantic context is absent, unbounded or internally inconsistent.
    #[error("provider semantic context is invalid")]
    InvalidSemanticContext,
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
