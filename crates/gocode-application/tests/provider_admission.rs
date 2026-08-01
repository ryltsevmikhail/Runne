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
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchError, DispatchRequest, ModelRef,
    PrepareError, PreparedProviderRecord, PreparedRequest, ProviderCall, ProviderCallDigestVersion,
    ProviderCallId, ProviderCapability, ProviderDispatchClaim, ProviderDispatchRepository,
    ProviderFuture, ProviderId, ProviderPort, ProviderPreEffectRejection,
    ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderRepositoryState,
    ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem,
    ReconcileRequest, ReconciliationDisposition, ScriptedProvider, StreamCursor, StreamError,
};

fn call() -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-28",
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
        principal_id: "provider-principal".to_owned(),
        conversation_id: ConversationId::from_bytes([3; 16]),
        taskrun_id: TaskRunId::from_bytes([4; 16]),
        execution_attempt_id: AttemptId::from_bytes([5; 16]),
        profile_digest: [6; 32],
        pricing_revision_digest: [7; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".to_owned(),
        provider_idempotency_key: "provider-attempt-5".to_owned(),
    }
}

struct AvailableGuard;

impl ProhibitedContentPort for AvailableGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

#[test]
fn authority_reference_rejects_zero_identity_and_revision() {
    assert!(ProviderEffectAuthorityRef::new([0; 16], 1).is_err());
    assert!(ProviderEffectAuthorityRef::new([10; 16], 0).is_err());
}

#[derive(Default)]
struct RecordingRepository {
    existing_prepared: Mutex<Option<PreparedProviderRecord>>,
    persisted_records: Mutex<Vec<PreparedProviderRecord>>,
    claim_count: Mutex<usize>,
    streaming_count: Mutex<usize>,
    rejected: Mutex<Vec<ProviderPreEffectRejection>>,
    uncertain_count: Mutex<usize>,
}

impl RecordingRepository {
    fn existing_v1() -> Self {
        let prepared =
            PreparedRequest::from_call_for_digest_version(&call(), ProviderCallDigestVersion::V1)
                .unwrap();
        Self {
            existing_prepared: Mutex::new(Some(PreparedProviderRecord {
                call_id: call().call_id(),
                call_digest_version: ProviderCallDigestVersion::V1,
                prepared_digest: *prepared.request_ref().as_bytes(),
                render_digest: *prepared.render_digest(),
                profile_digest: [6; 32],
            })),
            ..Self::default()
        }
    }
}

impl ProviderDispatchRepository for RecordingRepository {
    fn load_prepared(
        &self,
        _call_id: ProviderCallId,
    ) -> Result<Option<PreparedProviderRecord>, ProviderRepositoryError> {
        Ok(*self.existing_prepared.lock().unwrap())
    }

    fn persist_prepared(
        &self,
        record: &PreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        self.persisted_records.lock().unwrap().push(*record);
        Ok(())
    }

    fn claim(
        &self,
        _claim: &ProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        *self.claim_count.lock().unwrap() += 1;
        panic!("coordinator must not claim after runtime issuance")
    }

    fn mark_streaming(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        *self.streaming_count.lock().unwrap() += 1;
        Ok(())
    }

    fn mark_rejected_before_effect(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        rejection: ProviderPreEffectRejection,
    ) -> Result<(), ProviderRepositoryError> {
        self.rejected.lock().unwrap().push(rejection);
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
        *self.uncertain_count.lock().unwrap() += 1;
        Ok(())
    }
}

#[derive(Clone)]
enum IssuerMode {
    Winner,
    Existing(ProviderRepositoryState),
    Reject(ProviderAdmissionError),
}

struct RecordingIssuer {
    mode: IssuerMode,
    count: Mutex<usize>,
}

impl RecordingIssuer {
    fn winner() -> Self {
        Self {
            mode: IssuerMode::Winner,
            count: Mutex::new(0),
        }
    }

    fn existing(state: ProviderRepositoryState) -> Self {
        Self {
            mode: IssuerMode::Existing(state),
            count: Mutex::new(0),
        }
    }

    fn rejecting(error: ProviderAdmissionError) -> Self {
        Self {
            mode: IssuerMode::Reject(error),
            count: Mutex::new(0),
        }
    }
}

impl RuntimeProviderAuthorityIssuer for RecordingIssuer {
    fn issue_decision(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssuerDecision, ProviderAdmissionError> {
        *self.count.lock().unwrap() += 1;
        match &self.mode {
            IssuerMode::Winner => {
                let claim = ProviderDispatchClaim {
                    call_id: request.prepared.call_id,
                    attempt_id: DispatchAttemptId::from_bytes([8; 16]),
                    permit_id: [9; 16],
                    prepared_digest: request.prepared.prepared_digest,
                    render_digest: request.prepared.render_digest,
                    profile_digest: request.prepared.profile_digest,
                    token_reservation_id: [10; 16],
                    cost_reservation_id: [11; 16],
                    fencing_token: 12,
                    provider_idempotency_key: request.provider_idempotency_key.clone(),
                };
                ProviderAuthorityIssuerDecision::from_durable_commit(
                    request,
                    ProviderEffectAuthorityRef::new([13; 16], 1).unwrap(),
                    12,
                    claim,
                )
            }
            IssuerMode::Existing(state) => Ok(ProviderAuthorityIssuerDecision::existing(*state)),
            IssuerMode::Reject(error) => Err(error.clone()),
        }
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
fn authority_rejections_prevent_adapter_dispatch_without_partial_claim() {
    let failures = [
        ProviderAdmissionError::CapabilityDenied,
        ProviderAdmissionError::ApprovalDenied,
        ProviderAdmissionError::ApprovalExpired,
        ProviderAdmissionError::TokenBudgetDenied,
        ProviderAdmissionError::CostBudgetDenied,
        ProviderAdmissionError::PricingRevisionMismatch,
        ProviderAdmissionError::StaleFencingToken,
    ];

    for failure in failures {
        let repository = RecordingRepository::default();
        let issuer = RecordingIssuer::rejecting(failure.clone());
        let adapter = adapter();
        let coordinator =
            ProviderDispatchCoordinator::new(&repository, &issuer, &adapter, &AvailableGuard);

        assert_eq!(block_on(coordinator.dispatch(request())), Err(failure));
        assert_eq!(adapter.dispatch_count(), 0);
        assert_eq!(*repository.claim_count.lock().unwrap(), 0);
        assert!(repository.rejected.lock().unwrap().is_empty());
        assert_eq!(*repository.uncertain_count.lock().unwrap(), 0);
    }
}

#[test]
fn exact_issuance_replay_returns_state_without_adapter_dispatch() {
    let repository = RecordingRepository::default();
    let issuer = RecordingIssuer::existing(ProviderRepositoryState::Dispatching);
    let adapter = adapter();
    let coordinator =
        ProviderDispatchCoordinator::new(&repository, &issuer, &adapter, &AvailableGuard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Existing {
            state: ProviderRepositoryState::Dispatching,
        }
    );
    assert_eq!(*issuer.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn released_v1_replay_uses_stored_digest_domain() {
    let repository = RecordingRepository::existing_v1();
    let issuer = RecordingIssuer::existing(ProviderRepositoryState::Dispatching);
    let adapter = adapter();
    let coordinator =
        ProviderDispatchCoordinator::new(&repository, &issuer, &adapter, &AvailableGuard);

    assert!(matches!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Existing { .. }
    ));
    assert_eq!(
        repository.persisted_records.lock().unwrap().as_slice(),
        &[repository.existing_prepared.lock().unwrap().unwrap()]
    );
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn issuer_winner_dispatches_once() {
    let repository = RecordingRepository::default();
    let issuer = RecordingIssuer::winner();
    let adapter = adapter();
    let coordinator =
        ProviderDispatchCoordinator::new(&repository, &issuer, &adapter, &AvailableGuard);

    assert!(matches!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Streaming { .. }
    ));
    assert_eq!(*issuer.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 1);
    assert_eq!(*repository.streaming_count.lock().unwrap(), 1);
    assert_eq!(*repository.claim_count.lock().unwrap(), 0);
}

#[derive(Clone)]
struct DispatchFailureProvider {
    error: DispatchError,
}

impl ProviderPort for DispatchFailureProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, digest_version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        let error = self.error.clone();
        Box::pin(async move { Err(error) })
    }

    fn next<'a>(
        &'a self,
        _stream: &'a ProviderStreamId,
        _cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { unreachable!("dispatch failure has no stream") })
    }

    fn cancel(
        &self,
        _request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch failure cannot be cancelled") })
    }

    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch failure is not reconciled here") })
    }
}

#[test]
fn adapter_pre_effect_rejection_is_terminal_without_uncertain_effect() {
    let repository = RecordingRepository::default();
    let issuer = RecordingIssuer::winner();
    let adapter = DispatchFailureProvider {
        error: DispatchError::RejectedBeforeEffect(
            ProviderPreEffectRejection::CredentialUnavailable,
        ),
    };
    let coordinator =
        ProviderDispatchCoordinator::new(&repository, &issuer, &adapter, &AvailableGuard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::RejectedBeforeEffect {
            reason: ProviderPreEffectRejection::CredentialUnavailable,
        }
    );
    assert_eq!(
        repository.rejected.lock().unwrap().as_slice(),
        &[ProviderPreEffectRejection::CredentialUnavailable]
    );
    assert_eq!(*repository.uncertain_count.lock().unwrap(), 0);
}

#[test]
fn maybe_dispatched_adapter_failure_is_persisted_as_uncertain() {
    let repository = RecordingRepository::default();
    let issuer = RecordingIssuer::winner();
    let adapter = DispatchFailureProvider {
        error: DispatchError::MaybeDispatched,
    };
    let coordinator =
        ProviderDispatchCoordinator::new(&repository, &issuer, &adapter, &AvailableGuard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Uncertain
    );
    assert!(repository.rejected.lock().unwrap().is_empty());
    assert_eq!(*repository.uncertain_count.lock().unwrap(), 1);
}
