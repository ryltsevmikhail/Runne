use std::sync::Mutex;

use futures::executor::block_on;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::{
    ProviderAdmissionError, ProviderCoordinatorOutcome, ProviderCoordinatorRequest,
    ProviderDispatchCoordinator, ProviderEffectAdmission, ProviderEffectAuthorityRef,
    ProviderEffectRequest,
};
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
        authority_ref: authority_ref(),
        profile_digest: [4; 32],
        attempt_id: DispatchAttemptId::from_bytes([5; 16]),
        permit_id: [6; 16],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        fencing_token: 9,
        owner_id: "provider-owner".to_owned(),
        scope: "provider.dispatch".to_owned(),
        provider_idempotency_key: "provider-attempt-5".to_owned(),
    }
}

fn authority_ref() -> ProviderEffectAuthorityRef {
    ProviderEffectAuthorityRef::new([10; 16], 1).unwrap()
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

#[test]
fn provider_request_has_no_caller_supplied_grant_string() {
    let request = request();
    let prepared = PreparedRequest::from_call(&request.call).unwrap();
    let _ = ProviderEffectRequest {
        authority_ref: request.authority_ref,
        attempt_id: request.attempt_id,
        permit_id: request.permit_id,
        prepared_digest: [2; 32],
        render_digest: *prepared.render_digest(),
        profile_digest: request.profile_digest,
        token_reservation_id: request.token_reservation_id,
        cost_reservation_id: request.cost_reservation_id,
        fencing_token: request.fencing_token,
        owner_id: request.owner_id,
        scope: request.scope,
    };
}

#[derive(Default)]
struct RecordingRepository {
    claim_outcome: Mutex<Option<ProviderRepositoryClaimOutcome>>,
    existing_prepared: Mutex<Option<PreparedProviderRecord>>,
    persisted_records: Mutex<Vec<PreparedProviderRecord>>,
    prepared_count: Mutex<usize>,
    claim_count: Mutex<usize>,
    streaming_count: Mutex<usize>,
    rejected: Mutex<Vec<ProviderPreEffectRejection>>,
    uncertain_count: Mutex<usize>,
}

impl RecordingRepository {
    fn winner() -> Self {
        Self {
            claim_outcome: Mutex::new(Some(ProviderRepositoryClaimOutcome::Winner {
                permit_id: [6; 16],
            })),
            ..Self::default()
        }
    }

    fn existing() -> Self {
        Self {
            claim_outcome: Mutex::new(Some(ProviderRepositoryClaimOutcome::Existing {
                attempt_id: DispatchAttemptId::from_bytes([5; 16]),
                state: ProviderRepositoryState::Dispatching,
            })),
            ..Self::default()
        }
    }

    fn existing_v1() -> Self {
        let prepared =
            PreparedRequest::from_call_for_digest_version(&call(), ProviderCallDigestVersion::V1)
                .unwrap();
        Self {
            claim_outcome: Mutex::new(Some(ProviderRepositoryClaimOutcome::Existing {
                attempt_id: DispatchAttemptId::from_bytes([5; 16]),
                state: ProviderRepositoryState::Dispatching,
            })),
            existing_prepared: Mutex::new(Some(PreparedProviderRecord {
                call_id: call().call_id(),
                call_digest_version: ProviderCallDigestVersion::V1,
                prepared_digest: *prepared.request_ref().as_bytes(),
                render_digest: *prepared.render_digest(),
                profile_digest: [4; 32],
            })),
            ..Self::default()
        }
    }

    fn record_streaming(&self) {
        *self.streaming_count.lock().unwrap() += 1;
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
        *self.prepared_count.lock().unwrap() += 1;
        self.persisted_records.lock().unwrap().push(*record);
        Ok(())
    }

    fn claim(
        &self,
        _claim: &ProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        *self.claim_count.lock().unwrap() += 1;
        Ok(self.claim_outcome.lock().unwrap().clone().unwrap())
    }

    fn mark_streaming(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _stream_id: gocode_provider::ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        self.record_streaming();
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

struct RecordingAdmission {
    result: Result<(), ProviderAdmissionError>,
    count: Mutex<usize>,
}

impl RecordingAdmission {
    fn allowing() -> Self {
        Self {
            result: Ok(()),
            count: Mutex::new(0),
        }
    }

    fn rejecting(error: ProviderAdmissionError) -> Self {
        Self {
            result: Err(error),
            count: Mutex::new(0),
        }
    }
}

impl ProviderEffectAdmission for RecordingAdmission {
    fn admit(&self, _request: &ProviderEffectRequest) -> Result<(), ProviderAdmissionError> {
        *self.count.lock().unwrap() += 1;
        self.result.clone()
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
fn every_admission_rejection_prevents_adapter_dispatch() {
    let failures = [
        ProviderAdmissionError::CapabilityDenied,
        ProviderAdmissionError::TokenReservationMismatch,
        ProviderAdmissionError::CostReservationMismatch,
        ProviderAdmissionError::RenderDigestMismatch,
        ProviderAdmissionError::PermitMismatch,
        ProviderAdmissionError::StaleFencingToken,
    ];

    for failure in failures {
        let repository = RecordingRepository::winner();
        let admission = RecordingAdmission::rejecting(failure.clone());
        let adapter = adapter();
        let guard = AvailableGuard;
        let coordinator =
            ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

        assert_eq!(block_on(coordinator.dispatch(request())), Err(failure));
        assert_eq!(adapter.dispatch_count(), 0);
        assert_eq!(repository.rejected.lock().unwrap().len(), 1);
        assert_eq!(*repository.uncertain_count.lock().unwrap(), 0);
    }
}

#[test]
fn claim_replay_verifies_admission_without_adapter_dispatch() {
    let repository = RecordingRepository::existing();
    let admission = RecordingAdmission::allowing();
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Existing {
            state: ProviderRepositoryState::Dispatching,
        }
    );
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn released_v1_claim_replay_uses_the_stored_digest_domain() {
    let repository = RecordingRepository::existing_v1();
    let admission = RecordingAdmission::allowing();
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Existing {
            state: ProviderRepositoryState::Dispatching,
        }
    );
    assert_eq!(
        repository.persisted_records.lock().unwrap().as_slice(),
        &[repository.existing_prepared.lock().unwrap().unwrap()]
    );
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn existing_claim_rejects_unknown_authority_without_adapter_dispatch() {
    let repository = RecordingRepository::existing();
    let admission = RecordingAdmission::rejecting(ProviderAdmissionError::AuthorityDenied);
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
    assert!(repository.rejected.lock().unwrap().is_empty());
    assert_eq!(*repository.uncertain_count.lock().unwrap(), 0);
}

#[test]
fn existing_claim_rejects_changed_authority_without_adapter_dispatch() {
    let repository = RecordingRepository::existing();
    let admission = RecordingAdmission::rejecting(ProviderAdmissionError::AuthorityConflict);
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
    assert!(repository.rejected.lock().unwrap().is_empty());
    assert_eq!(*repository.uncertain_count.lock().unwrap(), 0);
}

#[test]
fn winner_is_admitted_once_and_dispatches_once() {
    let repository = RecordingRepository::winner();
    let admission = RecordingAdmission::allowing();
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert!(matches!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Streaming { .. }
    ));
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 1);
    assert_eq!(*repository.streaming_count.lock().unwrap(), 1);
}

#[test]
fn post_claim_uncertainty_is_persisted_without_adapter_dispatch() {
    let repository = RecordingRepository::winner();
    let admission = RecordingAdmission::rejecting(ProviderAdmissionError::PostClaimUncertain);
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())),
        Ok(ProviderCoordinatorOutcome::Uncertain)
    );
    assert_eq!(*repository.uncertain_count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
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
    let repository = RecordingRepository::winner();
    let admission = RecordingAdmission::allowing();
    let adapter = DispatchFailureProvider {
        error: DispatchError::RejectedBeforeEffect(
            ProviderPreEffectRejection::CredentialUnavailable,
        ),
    };
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

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
    let repository = RecordingRepository::winner();
    let admission = RecordingAdmission::allowing();
    let adapter = DispatchFailureProvider {
        error: DispatchError::MaybeDispatched,
    };
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Uncertain
    );
    assert!(repository.rejected.lock().unwrap().is_empty());
    assert_eq!(*repository.uncertain_count.lock().unwrap(), 1);
}
