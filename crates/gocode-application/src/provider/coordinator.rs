use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchError, DispatchRequest, PreparedProviderRecord, ProviderCall, ProviderDispatchClaim,
    ProviderDispatchRepository, ProviderPort, ProviderPreEffectRejection, ProviderRepositoryState,
};

use crate::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};

use super::{
    ProviderAdmissionError, ProviderAuthorityIssueOutcome, ProviderExecutionBinding,
    RuntimeProviderAuthorityIssuer,
};

/// Complete application input for one provider prepare/claim/admit/dispatch.
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

/// Application-level provider dispatch outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCoordinatorOutcome {
    /// New adapter stream was opened.
    Streaming {
        /// Opaque runtime-owned execution and normalized stream binding.
        binding: ProviderExecutionBinding,
    },
    /// Exact replay observed an existing durable state.
    Existing {
        /// Existing repository state.
        state: ProviderRepositoryState,
    },
    /// Adapter proved that no external provider effect began.
    RejectedBeforeEffect {
        /// Closed non-secret rejection reason.
        reason: ProviderPreEffectRejection,
    },
    /// Post-claim disposition is ambiguous and progression must freeze.
    Uncertain,
}

/// Orders provider prepare, persistence, single-dispatch claim and admission.
pub struct ProviderDispatchCoordinator<'a, R, I, P: ?Sized> {
    repository: &'a R,
    issuer: &'a I,
    provider: &'a P,
    prohibited_content: &'a dyn ProhibitedContentPort,
}

impl<'a, R, I, P> ProviderDispatchCoordinator<'a, R, I, P>
where
    R: ProviderDispatchRepository,
    I: RuntimeProviderAuthorityIssuer,
    P: ProviderPort + ?Sized,
{
    /// Constructs a coordinator from inward-facing ports.
    pub const fn new(
        repository: &'a R,
        issuer: &'a I,
        provider: &'a P,
        prohibited_content: &'a dyn ProhibitedContentPort,
    ) -> Self {
        Self {
            repository,
            issuer,
            provider,
            prohibited_content,
        }
    }

    /// Executes the ordered fail-closed provider dispatch boundary.
    pub async fn dispatch(
        &self,
        request: ProviderCoordinatorRequest,
    ) -> Result<ProviderCoordinatorOutcome, ProviderAdmissionError> {
        let call_bytes =
            serde_json::to_vec(&request.call).map_err(|_| ProviderAdmissionError::PolicyDenied)?;
        match self
            .prohibited_content
            .inspect(CanonicalContentBoundary::OutboundDelivery, &call_bytes)
        {
            Ok(ContentDisposition::Allowed { .. }) => {}
            Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
                return Err(ProviderAdmissionError::PolicyDenied);
            }
        }
        let existing_prepared = self
            .repository
            .load_prepared(request.call.call_id())
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let prepared = match existing_prepared {
            Some(record) => self
                .provider
                .prepare_for_digest_version(&request.call, record.call_digest_version),
            None => self.provider.prepare(&request.call),
        }
        .map_err(|_| ProviderAdmissionError::PrepareRejected)?;
        let prepared_digest = *prepared.request_ref().as_bytes();
        let render_digest = *prepared.render_digest();
        let prepared_record = PreparedProviderRecord {
            call_id: request.call.call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest,
            render_digest,
            profile_digest: request.profile_digest,
        };
        self.repository
            .persist_prepared(&prepared_record)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let issue_request = request.authority_request(prepared_record)?;
        let admitted = match self.issuer.issue(&issue_request)? {
            ProviderAuthorityIssueOutcome::Winner(admitted) => admitted,
            ProviderAuthorityIssueOutcome::Existing { state } => {
                return Ok(ProviderCoordinatorOutcome::Existing { state });
            }
        };
        super::execution::validate_issued_claim(&request.call, &issue_request, admitted.claim())?;
        let execution_admission = admitted.clone();
        let claim: ProviderDispatchClaim = (*admitted).into_claim();
        let attempt_id = claim.attempt_id;
        let fencing_token = claim.fencing_token;
        let dispatch_request = match DispatchRequest::new(prepared, claim) {
            Ok(dispatch_request) => dispatch_request,
            Err(_) => {
                let _ = self.repository.mark_uncertain(attempt_id, fencing_token);
                return Ok(ProviderCoordinatorOutcome::Uncertain);
            }
        };

        match self.provider.dispatch(dispatch_request).await {
            Ok(stream_id) => {
                if self
                    .repository
                    .mark_streaming(attempt_id, fencing_token, stream_id)
                    .is_err()
                {
                    let _ = self.repository.mark_uncertain(attempt_id, fencing_token);
                    return Ok(ProviderCoordinatorOutcome::Uncertain);
                }
                let binding = match ProviderExecutionBinding::from_admitted(
                    &execution_admission,
                    prepared_record,
                    stream_id,
                ) {
                    Ok(binding) => binding,
                    Err(_) => {
                        let _ = self.repository.mark_uncertain(attempt_id, fencing_token);
                        return Ok(ProviderCoordinatorOutcome::Uncertain);
                    }
                };
                Ok(ProviderCoordinatorOutcome::Streaming { binding })
            }
            Err(DispatchError::RejectedBeforeEffect(reason)) => {
                if self
                    .repository
                    .mark_rejected_before_effect(attempt_id, fencing_token, reason)
                    .is_err()
                {
                    let _ = self.repository.mark_uncertain(attempt_id, fencing_token);
                    Ok(ProviderCoordinatorOutcome::Uncertain)
                } else {
                    Ok(ProviderCoordinatorOutcome::RejectedBeforeEffect { reason })
                }
            }
            Err(
                DispatchError::MaybeDispatched
                | DispatchError::AttemptConflict
                | DispatchError::StreamNotFound,
            ) => {
                let _ = self.repository.mark_uncertain(attempt_id, fencing_token);
                Ok(ProviderCoordinatorOutcome::Uncertain)
            }
        }
    }
}
