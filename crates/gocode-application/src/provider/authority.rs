use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{PreparedProviderRecord, ProviderDispatchClaim, ProviderRepositoryState};

use super::{ProviderAdmissionError, ProviderEffectAuthorityRef};

/// Semantic runtime context admitted for one provider effect.
///
/// The type deliberately has no authority, permit, reservation, grant,
/// owner/scope or fencing fields. Those values are resolved and allocated by
/// the runtime-owned issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuthorityIssueRequest {
    /// Authenticated principal identity from command context.
    pub principal_id: String,
    /// Owning Conversation aggregate.
    pub conversation_id: ConversationId,
    /// Owning TaskRun aggregate.
    pub taskrun_id: TaskRunId,
    /// Owning domain execution attempt.
    pub execution_attempt_id: AttemptId,
    /// Exact non-secret prepared request evidence.
    pub prepared: PreparedProviderRecord,
    /// Immutable pricing revision digest.
    pub pricing_revision_digest: [u8; 32],
    /// Requested input-token reservation.
    pub requested_input_tokens: u64,
    /// Requested output-token reservation.
    pub requested_output_tokens: u64,
    /// Exact worst-case cost ceiling in micros of `currency`.
    pub max_cost_micros: u64,
    /// ISO-style uppercase currency code used by the pricing profile.
    pub currency: String,
    /// Stable semantic retry identity.
    pub provider_idempotency_key: String,
}

impl ProviderAuthorityIssueRequest {
    /// Validates bounded semantic input before runtime authority evaluation.
    pub fn validate(&self) -> Result<(), ProviderAdmissionError> {
        if self.principal_id.is_empty()
            || self.principal_id.len() > 256
            || self
                .principal_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || self.requested_output_tokens == 0
            || self.max_cost_micros == 0
            || self.currency.len() != 3
            || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
            || self.provider_idempotency_key.is_empty()
            || self.provider_idempotency_key.len() > 256
            || self
                .provider_idempotency_key
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(ProviderAdmissionError::InvalidSemanticContext);
        }
        Ok(())
    }
}

/// Exact runtime-issued metadata admitted for one adapter dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedProviderDispatch {
    authority_ref: ProviderEffectAuthorityRef,
    claim: ProviderDispatchClaim,
}

impl AdmittedProviderDispatch {
    fn new(
        authority_ref: ProviderEffectAuthorityRef,
        claim: ProviderDispatchClaim,
    ) -> Result<Self, ProviderAdmissionError> {
        if claim.permit_id == [0; 16]
            || claim.token_reservation_id == [0; 16]
            || claim.cost_reservation_id == [0; 16]
            || claim.fencing_token == 0
            || claim.provider_idempotency_key.is_empty()
            || claim.provider_idempotency_key.len() > 256
            || claim
                .provider_idempotency_key
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        Ok(Self {
            authority_ref,
            claim,
        })
    }

    /// Returns the opaque durable authority reference.
    pub const fn authority_ref(&self) -> ProviderEffectAuthorityRef {
        self.authority_ref
    }

    /// Returns the exact durable provider claim.
    pub const fn claim(&self) -> &ProviderDispatchClaim {
        &self.claim
    }

    /// Consumes the admitted metadata into its provider claim.
    pub fn into_claim(self) -> ProviderDispatchClaim {
        self.claim
    }
}

/// Raw issuer decision converted to dispatch authority inside application code.
///
/// This type is an implementation boundary for trusted issuer ports; only the
/// default [`RuntimeProviderAuthorityIssuer::issue`] method can construct
/// [`AdmittedProviderDispatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAuthorityIssuerDecision {
    /// Issuer atomically committed a new authority and claim.
    Winner {
        /// Durable runtime-issued authority.
        authority_ref: ProviderEffectAuthorityRef,
        /// Exact winner-only claim.
        claim: Box<ProviderDispatchClaim>,
    },
    /// Exact replay observed an existing durable state.
    Existing {
        /// Existing provider attempt state.
        state: ProviderRepositoryState,
    },
}

/// Atomic runtime authority issuance outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAuthorityIssueOutcome {
    /// This caller won one durable admission and may cross the adapter boundary.
    Winner(Box<AdmittedProviderDispatch>),
    /// Exact semantic replay observed an existing durable state and receives no
    /// permit.
    Existing {
        /// Existing provider attempt state.
        state: ProviderRepositoryState,
    },
}

/// Runtime-only authority, reservation and claim issuer.
///
/// Implementations derive owner/scope, read the current generation/fence,
/// evaluate capability/approval/pricing and commit every pre-effect record in
/// one durable transaction.
pub trait RuntimeProviderAuthorityIssuer: Send + Sync {
    /// Resolves the trusted issuer implementation decision.
    fn issue_decision(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssuerDecision, ProviderAdmissionError>;

    /// Atomically admits one exact provider effect or returns a typed denial.
    fn issue(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssueOutcome, ProviderAdmissionError> {
        match self.issue_decision(request)? {
            ProviderAuthorityIssuerDecision::Winner {
                authority_ref,
                claim,
            } => Ok(ProviderAuthorityIssueOutcome::Winner(Box::new(
                AdmittedProviderDispatch::new(authority_ref, *claim)?,
            ))),
            ProviderAuthorityIssuerDecision::Existing { state } => {
                Ok(ProviderAuthorityIssueOutcome::Existing { state })
            }
        }
    }
}
