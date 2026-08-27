use runne_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderCoordinatorRequest,
};
use runne_provider::{PreparedProviderRecord, ProviderDispatchClaim};

pub(super) fn issue_request(
    request: &ProviderCoordinatorRequest,
    prepared: PreparedProviderRecord,
) -> Result<ProviderAuthorityIssueRequest, ProviderAdmissionError> {
    if request.requested_output_tokens != request.call.max_output_tokens() {
        return Err(ProviderAdmissionError::InvalidSemanticContext);
    }
    let issue = ProviderAuthorityIssueRequest {
        provider_id: request.call.model_ref().provider_id().clone(),
        principal_id: request.principal_id.clone(),
        conversation_id: request.conversation_id,
        taskrun_id: request.taskrun_id,
        execution_attempt_id: request.execution_attempt_id,
        prepared,
        pricing_revision_digest: request.pricing_revision_digest,
        requested_input_tokens: request.requested_input_tokens,
        requested_output_tokens: u64::from(request.requested_output_tokens),
        max_cost_micros: request.max_cost_micros,
        currency: request.currency.clone(),
        provider_idempotency_key: request.provider_idempotency_key.clone(),
    };
    issue.validate()?;
    Ok(issue)
}

pub(super) fn claim_matches(
    request: &ProviderCoordinatorRequest,
    issue: &ProviderAuthorityIssueRequest,
    claim: &ProviderDispatchClaim,
) -> bool {
    claim.call_id == request.call.call_id()
        && claim.prepared_digest == issue.prepared.prepared_digest
        && claim.render_digest == issue.prepared.render_digest
        && claim.profile_digest == issue.prepared.profile_digest
        && claim.provider_idempotency_key == issue.provider_idempotency_key
}
