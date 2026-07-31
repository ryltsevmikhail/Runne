use std::sync::Mutex;

use futures::executor::block_on;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderAuthorityIssuerDecision,
    ProviderCoordinatorOutcome, ProviderCoordinatorRequest, ProviderDispatchCoordinator,
    ProviderEffectAuthorityRef, RuntimeProviderAuthorityIssuer,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchAttemptId, MAX_PROVIDER_USAGE_TOKENS, ModelRef, PreparedProviderRecord, ProviderCall,
    ProviderCallId, ProviderCapability, ProviderDispatchClaim, ProviderDispatchRepository,
    ProviderPort, ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderRepositoryState,
    ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId, ScriptedProvider,
};

fn call() -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(
            gocode_provider::ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-31",
        )
        .unwrap(),
        [2; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

fn request() -> ProviderCoordinatorRequest {
    ProviderCoordinatorRequest {
        call: call(),
        principal_id: "principal-1".to_owned(),
        conversation_id: ConversationId::from_bytes([3; 16]),
        taskrun_id: TaskRunId::from_bytes([4; 16]),
        execution_attempt_id: AttemptId::from_bytes([5; 16]),
        profile_digest: [6; 32],
        pricing_revision_digest: [7; 32],
        requested_input_tokens: 256,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".to_owned(),
        provider_idempotency_key: "semantic-provider-attempt-1".to_owned(),
    }
}

fn admitted_claim() -> ProviderDispatchClaim {
    ProviderDispatchClaim {
        call_id: ProviderCallId::from_bytes([1; 16]),
        attempt_id: DispatchAttemptId::from_bytes([9; 16]),
        permit_id: [10; 16],
        prepared_digest: [0; 32],
        render_digest: [0; 32],
        profile_digest: [6; 32],
        token_reservation_id: [11; 16],
        cost_reservation_id: [12; 16],
        fencing_token: 13,
        provider_idempotency_key: "semantic-provider-attempt-1".to_owned(),
    }
}

struct AllowingGuard;

impl ProhibitedContentPort for AllowingGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

#[derive(Default)]
struct RecordingRepository {
    persisted: Mutex<Vec<PreparedProviderRecord>>,
    claim_count: Mutex<usize>,
    streaming: Mutex<Vec<(DispatchAttemptId, u64, ProviderStreamId)>>,
}

impl ProviderDispatchRepository for RecordingRepository {
    fn load_prepared(
        &self,
        _call_id: ProviderCallId,
    ) -> Result<Option<PreparedProviderRecord>, ProviderRepositoryError> {
        Ok(None)
    }

    fn persist_prepared(
        &self,
        record: &PreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        self.persisted.lock().unwrap().push(*record);
        Ok(())
    }

    fn claim(
        &self,
        _claim: &ProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        *self.claim_count.lock().unwrap() += 1;
        panic!("coordinator must not perform a second claim")
    }

    fn mark_streaming(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        self.streaming
            .lock()
            .unwrap()
            .push((attempt_id, fencing_token, stream_id));
        Ok(())
    }

    fn mark_rejected_before_effect(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _rejection: gocode_provider::ProviderPreEffectRejection,
    ) -> Result<(), ProviderRepositoryError> {
        Ok(())
    }

    fn mark_terminal_pending(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        Ok(())
    }

    fn settle(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        Ok(())
    }

    fn mark_uncertain(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError> {
        Ok(())
    }
}

struct RecordingIssuer {
    outcome: Result<ProviderAuthorityIssuerDecision, ProviderAdmissionError>,
    requests: Mutex<Vec<ProviderAuthorityIssueRequest>>,
}

impl RuntimeProviderAuthorityIssuer for RecordingIssuer {
    fn issue_decision(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssuerDecision, ProviderAdmissionError> {
        self.requests.lock().unwrap().push(request.clone());
        self.outcome.clone()
    }
}

fn adapter() -> ScriptedProvider {
    ScriptedProvider::new(
        [ProviderCapability::Streaming],
        vec![ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap()],
    )
    .unwrap()
}

#[test]
fn semantic_request_exposes_no_authority_permit_reservation_or_fence_fields() {
    let request = request();

    assert_eq!(request.principal_id, "principal-1");
    assert_eq!(
        request.requested_output_tokens,
        request.call.max_output_tokens()
    );
    assert_eq!(
        request.provider_idempotency_key,
        "semantic-provider-attempt-1"
    );
}

#[test]
fn all_runtime_authority_denials_prevent_adapter_dispatch_and_second_claim() {
    let denials = [
        ProviderAdmissionError::CapabilityDenied,
        ProviderAdmissionError::ApprovalDenied,
        ProviderAdmissionError::ApprovalExpired,
        ProviderAdmissionError::TokenBudgetDenied,
        ProviderAdmissionError::CostBudgetDenied,
        ProviderAdmissionError::PricingRevisionMismatch,
        ProviderAdmissionError::StaleFencingToken,
    ];

    for denial in denials {
        let repository = RecordingRepository::default();
        let issuer = RecordingIssuer {
            outcome: Err(denial.clone()),
            requests: Mutex::new(Vec::new()),
        };
        let provider = adapter();
        let coordinator =
            ProviderDispatchCoordinator::new(&repository, &issuer, &provider, &AllowingGuard);

        assert_eq!(block_on(coordinator.dispatch(request())), Err(denial));
        assert_eq!(provider.dispatch_count(), 0);
        assert_eq!(*repository.claim_count.lock().unwrap(), 0);
        assert_eq!(issuer.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn issuer_winner_is_the_only_claim_dispatched_and_fences_state_updates() {
    let repository = RecordingRepository::default();
    let provider = adapter();
    let prepared = provider.prepare(&request().call).unwrap();
    let claim = ProviderDispatchClaim {
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        ..admitted_claim()
    };
    let expected_attempt_id = claim.attempt_id;
    let expected_fencing_token = claim.fencing_token;
    let issuer = RecordingIssuer {
        outcome: Ok(ProviderAuthorityIssuerDecision::Winner {
            authority_ref: ProviderEffectAuthorityRef::new([8; 16], 1).unwrap(),
            claim: Box::new(claim),
        }),
        requests: Mutex::new(Vec::new()),
    };
    let coordinator =
        ProviderDispatchCoordinator::new(&repository, &issuer, &provider, &AllowingGuard);

    assert!(matches!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Streaming { .. }
    ));
    assert_eq!(provider.dispatch_count(), 1);
    assert_eq!(*repository.claim_count.lock().unwrap(), 0);
    assert_eq!(
        repository.streaming.lock().unwrap()[0].0,
        expected_attempt_id
    );
    assert_eq!(
        repository.streaming.lock().unwrap()[0].1,
        expected_fencing_token
    );
}

#[test]
fn exact_issuance_replay_never_reenters_adapter() {
    let repository = RecordingRepository::default();
    let issuer = RecordingIssuer {
        outcome: Ok(ProviderAuthorityIssuerDecision::Existing {
            state: ProviderRepositoryState::Streaming,
        }),
        requests: Mutex::new(Vec::new()),
    };
    let provider = adapter();
    let coordinator =
        ProviderDispatchCoordinator::new(&repository, &issuer, &provider, &AllowingGuard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Existing {
            state: ProviderRepositoryState::Streaming,
        }
    );
    assert_eq!(provider.dispatch_count(), 0);
    assert_eq!(*repository.claim_count.lock().unwrap(), 0);
}

#[test]
fn oversized_token_reservations_are_rejected_before_authority_or_dispatch() {
    for oversized_output in [false, true] {
        let repository = RecordingRepository::default();
        let issuer = RecordingIssuer {
            outcome: Ok(ProviderAuthorityIssuerDecision::Existing {
                state: ProviderRepositoryState::Streaming,
            }),
            requests: Mutex::new(Vec::new()),
        };
        let provider = adapter();
        let coordinator =
            ProviderDispatchCoordinator::new(&repository, &issuer, &provider, &AllowingGuard);
        let mut request = request();
        if oversized_output {
            let output = u32::try_from(MAX_PROVIDER_USAGE_TOKENS + 1).unwrap();
            request.call = ProviderCall::new(
                ProviderCallId::from_bytes([1; 16]),
                request.call.model_ref().clone(),
                [2; 32],
                output,
                serde_json::Value::Null,
            )
            .unwrap()
            .with_required_capabilities(vec![ProviderCapability::Streaming]);
            request.requested_output_tokens = output;
        } else {
            request.requested_input_tokens = MAX_PROVIDER_USAGE_TOKENS + 1;
        }

        assert_eq!(
            block_on(coordinator.dispatch(request)),
            Err(ProviderAdmissionError::InvalidSemanticContext)
        );
        assert!(issuer.requests.lock().unwrap().is_empty());
        assert_eq!(provider.dispatch_count(), 0);
        assert_eq!(*repository.claim_count.lock().unwrap(), 0);
    }
}
