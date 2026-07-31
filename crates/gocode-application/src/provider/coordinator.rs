use gocode_provider::{
    DispatchError, DispatchRequest, PreparedProviderRecord, ProviderCall, ProviderDispatchClaim,
    ProviderDispatchRepository, ProviderPort, ProviderPreEffectRejection,
    ProviderRepositoryClaimOutcome, ProviderRepositoryState, ProviderStreamId,
};

use crate::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};

use super::{
    ProviderAdmissionError, ProviderEffectAdmission, ProviderEffectAuthorityRef,
    ProviderEffectRequest,
};

/// Complete application input for one provider prepare/claim/admit/dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderCoordinatorRequest {
    /// Normalized provider call.
    pub call: ProviderCall,
    /// Issuer-created, revision-bound authority for provider dispatch.
    pub authority_ref: ProviderEffectAuthorityRef,
    /// Exact provider adapter/model profile digest.
    pub profile_digest: [u8; 32],
    /// Durable dispatch attempt.
    pub attempt_id: gocode_provider::DispatchAttemptId,
    /// Winner-only permit identity.
    pub permit_id: [u8; 16],
    /// Token budget reservation.
    pub token_reservation_id: [u8; 16],
    /// Cost budget reservation.
    pub cost_reservation_id: [u8; 16],
    /// Current non-zero worker fencing token.
    pub fencing_token: u64,
    /// Caller identity reference verified against the authority issuer's owner.
    pub owner_id: String,
    /// Requested authority scope reference.
    pub scope: String,
    /// Stable provider idempotency key.
    pub provider_idempotency_key: String,
}

/// Application-level provider dispatch outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCoordinatorOutcome {
    /// New adapter stream was opened.
    Streaming {
        /// Normalized stream identity.
        stream_id: ProviderStreamId,
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
pub struct ProviderDispatchCoordinator<'a, R, A, P> {
    repository: &'a R,
    admission: &'a A,
    provider: &'a P,
    prohibited_content: &'a dyn ProhibitedContentPort,
}

impl<'a, R, A, P> ProviderDispatchCoordinator<'a, R, A, P>
where
    R: ProviderDispatchRepository,
    A: ProviderEffectAdmission,
    P: ProviderPort,
{
    /// Constructs a coordinator from inward-facing ports.
    pub const fn new(
        repository: &'a R,
        admission: &'a A,
        provider: &'a P,
        prohibited_content: &'a dyn ProhibitedContentPort,
    ) -> Self {
        Self {
            repository,
            admission,
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
        self.repository
            .persist_prepared(&PreparedProviderRecord {
                call_id: request.call.call_id(),
                call_digest_version: prepared.request_ref().digest_version(),
                prepared_digest,
                render_digest,
                profile_digest: request.profile_digest,
            })
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let claim = ProviderDispatchClaim {
            call_id: request.call.call_id(),
            attempt_id: request.attempt_id,
            permit_id: request.permit_id,
            prepared_digest,
            render_digest,
            profile_digest: request.profile_digest,
            token_reservation_id: request.token_reservation_id,
            cost_reservation_id: request.cost_reservation_id,
            fencing_token: request.fencing_token,
            provider_idempotency_key: request.provider_idempotency_key,
        };
        let (permit_id, existing_state) = match self
            .repository
            .claim(&claim)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        {
            ProviderRepositoryClaimOutcome::Winner { permit_id } => (permit_id, None),
            ProviderRepositoryClaimOutcome::Existing { state, .. } => {
                (request.permit_id, Some(state))
            }
        };
        if permit_id != request.permit_id {
            return Err(ProviderAdmissionError::PermitMismatch);
        }
        let effect = ProviderEffectRequest {
            authority_ref: request.authority_ref,
            attempt_id: request.attempt_id,
            permit_id,
            prepared_digest,
            render_digest,
            profile_digest: request.profile_digest,
            token_reservation_id: request.token_reservation_id,
            cost_reservation_id: request.cost_reservation_id,
            fencing_token: request.fencing_token,
            owner_id: request.owner_id,
            scope: request.scope,
        };
        if let Err(error) = self.admission.admit(&effect) {
            if existing_state.is_some() {
                return Err(error);
            }
            if matches!(
                error,
                ProviderAdmissionError::PostClaimUncertain
                    | ProviderAdmissionError::RepositoryFailure
            ) {
                self.repository
                    .mark_uncertain(request.attempt_id, request.fencing_token)
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                return Ok(ProviderCoordinatorOutcome::Uncertain);
            }
            let rejection = match error {
                ProviderAdmissionError::CapabilityDenied => {
                    ProviderPreEffectRejection::CapabilityDenied
                }
                _ => ProviderPreEffectRejection::AdmissionRejected,
            };
            self.repository
                .mark_rejected_before_effect(request.attempt_id, request.fencing_token, rejection)
                .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
            return Err(error);
        }
        if let Some(state) = existing_state {
            return Ok(ProviderCoordinatorOutcome::Existing { state });
        }

        match self
            .provider
            .dispatch(
                DispatchRequest::new(prepared, claim)
                    .map_err(|_| ProviderAdmissionError::PolicyDenied)?,
            )
            .await
        {
            Ok(stream_id) => {
                if self
                    .repository
                    .mark_streaming(request.attempt_id, request.fencing_token, stream_id)
                    .is_err()
                {
                    self.repository
                        .mark_uncertain(request.attempt_id, request.fencing_token)
                        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                    return Ok(ProviderCoordinatorOutcome::Uncertain);
                }
                Ok(ProviderCoordinatorOutcome::Streaming { stream_id })
            }
            Err(DispatchError::RejectedBeforeEffect(reason)) => {
                self.repository
                    .mark_rejected_before_effect(request.attempt_id, request.fencing_token, reason)
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                Ok(ProviderCoordinatorOutcome::RejectedBeforeEffect { reason })
            }
            Err(
                DispatchError::MaybeDispatched
                | DispatchError::AttemptConflict
                | DispatchError::StreamNotFound,
            ) => {
                self.repository
                    .mark_uncertain(request.attempt_id, request.fencing_token)
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                Ok(ProviderCoordinatorOutcome::Uncertain)
            }
        }
    }
}
