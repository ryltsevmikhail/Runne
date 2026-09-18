use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{MAX_PROVIDER_USAGE_TOKENS, PreparedProviderRecord, ProviderId};

use super::ProviderAdmissionError;

/// Semantic runtime context admitted for one provider effect.
///
/// The type deliberately has no authority, permit, reservation, grant,
/// owner/scope or fencing fields. Those values are resolved and allocated by
/// the concrete runtime-owned store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAuthorityIssueRequest {
    /// Canonical provider selected before preparation and admission.
    pub provider_id: ProviderId,
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
            || (self.max_cost_micros == 0 && self.currency != "XXX")
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
