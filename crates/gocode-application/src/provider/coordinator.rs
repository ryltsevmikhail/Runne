use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::ProviderCall;

/// Complete application input for one provider prepare/claim/admit/dispatch.
///
/// Concrete dispatch coordination belongs to `gocode-store`, so callers cannot
/// inject an authority implementation at this application boundary.
///
/// ```compile_fail
/// use gocode_application::provider::ProviderDispatchCoordinator;
///
/// let _ = ProviderDispatchCoordinator::new;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderCoordinatorRequest {
    /// Normalized provider call.
    pub call: ProviderCall,
    /// Authenticated command principal.
    pub principal_id: String,
    /// Owning Conversation aggregate.
    pub conversation_id: ConversationId,
    /// Owning TaskRun aggregate.
    pub taskrun_id: TaskRunId,
    /// Owning domain execution attempt.
    pub execution_attempt_id: AttemptId,
    /// Exact provider adapter/model profile digest.
    pub profile_digest: [u8; 32],
    /// Exact immutable pricing revision digest.
    pub pricing_revision_digest: [u8; 32],
    /// Requested input-token reservation.
    pub requested_input_tokens: u64,
    /// Requested output-token reservation, equal to the call bound.
    pub requested_output_tokens: u32,
    /// Exact worst-case cost ceiling.
    pub max_cost_micros: u64,
    /// Uppercase three-byte currency code.
    pub currency: String,
    /// Stable provider idempotency key.
    pub provider_idempotency_key: String,
}
