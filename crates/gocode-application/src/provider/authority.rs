use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchAttemptId, MAX_PROVIDER_USAGE_TOKENS, PreparedProviderRecord,
    ProviderCallDigestVersion, ProviderDispatchClaim, ProviderRepositoryState, ProviderStreamId,
};

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
            || self.requested_input_tokens > MAX_PROVIDER_USAGE_TOKENS
            || self.requested_output_tokens == 0
            || self.requested_output_tokens > MAX_PROVIDER_USAGE_TOKENS
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
    runtime_generation: u64,
    claim: ProviderDispatchClaim,
}

impl AdmittedProviderDispatch {
    fn new(
        authority_ref: ProviderEffectAuthorityRef,
        runtime_generation: u64,
        claim: ProviderDispatchClaim,
    ) -> Result<Self, ProviderAdmissionError> {
        if claim.permit_id == [0; 16]
            || claim.token_reservation_id == [0; 16]
            || claim.cost_reservation_id == [0; 16]
            || claim.fencing_token == 0
            || runtime_generation == 0
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
            runtime_generation,
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

    /// Returns the runtime generation that admitted this effect.
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Consumes the admitted metadata into its provider claim.
    pub fn into_claim(self) -> ProviderDispatchClaim {
        self.claim
    }
}

/// Opaque runtime-issued binding for one admitted and opened provider stream.
///
/// The binding is constructed only by application coordination after the
/// runtime issuer returns a winner and the adapter opens the exact stream. It
/// carries no credential material and prevents hosts from rebuilding journal
/// authority from caller-selected fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderExecutionBinding {
    attempt_id: DispatchAttemptId,
    fencing_token: u64,
    runtime_generation: u64,
    call_digest_version: ProviderCallDigestVersion,
    prepared_digest: [u8; 32],
    profile_digest: [u8; 32],
    stream_id: ProviderStreamId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderExecutionBindingSeed {
    attempt_id: DispatchAttemptId,
    fencing_token: u64,
    runtime_generation: u64,
    call_digest_version: ProviderCallDigestVersion,
    prepared_digest: [u8; 32],
    profile_digest: [u8; 32],
}

impl ProviderExecutionBindingSeed {
    pub(crate) fn from_admitted(
        admitted: &AdmittedProviderDispatch,
        prepared: PreparedProviderRecord,
    ) -> Result<Self, ProviderAdmissionError> {
        if prepared.prepared_digest == [0; 32]
            || prepared.profile_digest == [0; 32]
            || admitted.claim.prepared_digest != prepared.prepared_digest
            || admitted.claim.profile_digest != prepared.profile_digest
        {
            return Err(ProviderAdmissionError::AuthorityConflict);
        }
        Ok(Self {
            attempt_id: admitted.claim.attempt_id,
            fencing_token: admitted.claim.fencing_token,
            runtime_generation: admitted.runtime_generation,
            call_digest_version: prepared.call_digest_version,
            prepared_digest: prepared.prepared_digest,
            profile_digest: prepared.profile_digest,
        })
    }

    pub(crate) const fn bind_stream(self, stream_id: ProviderStreamId) -> ProviderExecutionBinding {
        ProviderExecutionBinding {
            attempt_id: self.attempt_id,
            fencing_token: self.fencing_token,
            runtime_generation: self.runtime_generation,
            call_digest_version: self.call_digest_version,
            prepared_digest: self.prepared_digest,
            profile_digest: self.profile_digest,
            stream_id,
        }
    }
}

impl ProviderExecutionBinding {
    /// Returns the durable provider attempt identity.
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }

    /// Returns the runtime-issued fencing token.
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Returns the runtime generation that admitted the effect.
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Returns the exact provider-call digest domain.
    pub const fn call_digest_version(&self) -> ProviderCallDigestVersion {
        self.call_digest_version
    }

    /// Returns the exact credential-free prepared digest.
    pub const fn prepared_digest(&self) -> &[u8; 32] {
        &self.prepared_digest
    }

    /// Returns the exact immutable provider profile digest.
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    /// Returns the normalized adapter stream identity.
    pub const fn stream_id(&self) -> ProviderStreamId {
        self.stream_id
    }
}

/// Atomic issuance locator. It deliberately contains no dispatch authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAuthorityIssueLocator {
    /// A new admission was committed and must be independently reloaded.
    Committed {
        /// Exact durable provider attempt identity.
        attempt_id: DispatchAttemptId,
    },
    /// Exact semantic replay observed an existing durable state and receives no
    /// permit.
    Existing {
        /// Existing provider attempt state.
        state: ProviderRepositoryState,
    },
}

/// Raw non-secret fields independently reloaded from durable admission storage.
///
/// This is evidence, not dispatch authority. Only application validation can
/// convert it into an [`AdmittedProviderDispatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuthorityEvidence {
    /// Durable authority reference.
    pub authority_ref: ProviderEffectAuthorityRef,
    /// Runtime generation recorded by the authority transaction.
    pub runtime_generation: u64,
    /// Exact durable provider claim.
    pub claim: ProviderDispatchClaim,
}

/// Runtime-only authority, reservation and claim issuer.
///
/// Implementations derive owner/scope, read the current generation/fence,
/// evaluate capability/approval/pricing and commit every pre-effect record in
/// one durable transaction.
pub trait RuntimeProviderAuthorityIssuer: Send + Sync {
    /// Atomically commits admission or returns an existing durable state.
    fn issue_locator(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssueLocator, ProviderAdmissionError>;
}

/// Independent durable evidence boundary used after issuance and before effect.
pub trait RuntimeProviderAuthorityEvidenceVerifier: Send + Sync {
    /// Reloads the committed row and supplies its exact fields to the sink.
    fn verify_durable_admission(
        &self,
        request: &ProviderAuthorityIssueRequest,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderAuthorityEvidence, ProviderAdmissionError>;
}

pub(crate) fn verify_issued_authority<V: RuntimeProviderAuthorityEvidenceVerifier>(
    verifier: &V,
    request: &ProviderAuthorityIssueRequest,
    attempt_id: DispatchAttemptId,
) -> Result<AdmittedProviderDispatch, ProviderAdmissionError> {
    let evidence = verifier.verify_durable_admission(request, attempt_id)?;
    let admitted = AdmittedProviderDispatch::new(
        evidence.authority_ref,
        evidence.runtime_generation,
        evidence.claim,
    )?;
    if admitted.claim.attempt_id != attempt_id
        || admitted.claim.call_id != request.prepared.call_id
        || admitted.claim.prepared_digest != request.prepared.prepared_digest
        || admitted.claim.render_digest != request.prepared.render_digest
        || admitted.claim.profile_digest != request.prepared.profile_digest
        || admitted.claim.provider_idempotency_key != request.provider_idempotency_key
    {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(admitted)
}
