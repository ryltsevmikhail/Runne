use std::sync::Mutex;

use futures::executor::block_on;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderAuthorityIssuerDecision,
    ProviderCoordinatorRequest, ProviderDispatchCoordinator, RuntimeProviderAuthorityIssuer,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchAttemptId, DispatchError, DispatchRequest, ModelRef, PrepareError,
    PreparedProviderRecord, PreparedRequest, ProviderCall, ProviderCallId, ProviderDispatchClaim,
    ProviderDispatchRepository, ProviderFuture, ProviderId, ProviderPort,
    ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderStreamId,
};

const MARKER: &str = "task-seven-provider-marker";

#[derive(Clone, Copy)]
enum GuardMode {
    Marker,
    Unavailable,
}

struct BoundaryGuard(GuardMode);

impl ProhibitedContentPort for BoundaryGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self.0 {
            GuardMode::Unavailable => Err(ContentGuardError::Unavailable),
            GuardMode::Marker
                if bytes
                    .windows(MARKER.len())
                    .any(|window| window == MARKER.as_bytes()) =>
            {
                Ok(ContentDisposition::Prohibited { policy_epoch: 2 })
            }
            GuardMode::Marker => Ok(ContentDisposition::Allowed { policy_epoch: 2 }),
        }
    }
}

#[derive(Default)]
struct RecordingProvider {
    prepare_count: Mutex<usize>,
}

impl ProviderPort for RecordingProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        *self.prepare_count.lock().unwrap() += 1;
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: gocode_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        *self.prepare_count.lock().unwrap() += 1;
        PreparedRequest::from_call_for_digest_version(call, digest_version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!("policy-denied calls must not dispatch") })
    }

    fn next<'a>(
        &'a self,
        _stream_id: &'a ProviderStreamId,
        _cursor: gocode_provider::StreamCursor,
    ) -> ProviderFuture<'a, Result<gocode_provider::ProviderStreamItem, gocode_provider::StreamError>>
    {
        Box::pin(async { unreachable!("policy-denied calls must not poll") })
    }

    fn cancel(
        &self,
        _request: gocode_provider::CancelRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("policy-denied calls must not cancel") })
    }

    fn reconcile(
        &self,
        _request: gocode_provider::ReconcileRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("policy-denied calls must not reconcile") })
    }
}

#[derive(Default)]
struct RecordingRepository {
    persist_count: Mutex<usize>,
}

impl ProviderDispatchRepository for RecordingRepository {
    fn load_prepared(
        &self,
        _call_id: gocode_provider::ProviderCallId,
    ) -> Result<Option<PreparedProviderRecord>, ProviderRepositoryError> {
        unreachable!("policy-denied calls must not load prepared state")
    }

    fn persist_prepared(
        &self,
        _record: &PreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        *self.persist_count.lock().unwrap() += 1;
        unreachable!("policy-denied calls must not persist")
    }

    fn claim(
        &self,
        _claim: &ProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        unreachable!("policy-denied calls must not claim")
    }

    fn mark_streaming(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("policy-denied calls must not mark streaming")
    }

    fn mark_rejected_before_effect(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _rejection: gocode_provider::ProviderPreEffectRejection,
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("policy-denied calls must not mark rejected")
    }

    fn mark_terminal_pending(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("policy-denied calls must not mark terminal")
    }

    fn settle(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("policy-denied calls must not settle")
    }

    fn mark_uncertain(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("policy-denied calls must not mark uncertain")
    }
}

struct RecordingIssuer;

impl RuntimeProviderAuthorityIssuer for RecordingIssuer {
    fn issue_decision(
        &self,
        _request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssuerDecision, ProviderAdmissionError> {
        unreachable!("policy-denied calls must not reach admission")
    }
}

fn request() -> ProviderCoordinatorRequest {
    ProviderCoordinatorRequest {
        call: ProviderCall::new(
            ProviderCallId::from_bytes([1; 16]),
            ModelRef::new(
                ProviderId::new("synthetic-provider").unwrap(),
                "synthetic-model",
                "2026-07-30",
            )
            .unwrap(),
            [2; 32],
            128,
            serde_json::json!({"inert": MARKER}),
        )
        .unwrap(),
        principal_id: "principal".into(),
        conversation_id: ConversationId::from_bytes([3; 16]),
        taskrun_id: TaskRunId::from_bytes([4; 16]),
        execution_attempt_id: AttemptId::from_bytes([6; 16]),
        profile_digest: [5; 32],
        pricing_revision_digest: [7; 32],
        requested_input_tokens: 64,
        requested_output_tokens: 128,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: "provider-secret-boundary".into(),
    }
}

fn assert_denied_before_prepare(mode: GuardMode) {
    let repository = RecordingRepository::default();
    let issuer = RecordingIssuer;
    let provider = RecordingProvider::default();
    let guard = BoundaryGuard(mode);
    let coordinator = ProviderDispatchCoordinator::new(&repository, &issuer, &provider, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())),
        Err(ProviderAdmissionError::PolicyDenied)
    );
    assert_eq!(*provider.prepare_count.lock().unwrap(), 0);
    assert_eq!(*repository.persist_count.lock().unwrap(), 0);
}

#[test]
fn serialized_prohibited_provider_call_is_denied_before_prepare() {
    assert_denied_before_prepare(GuardMode::Marker);
}

#[test]
fn unavailable_provider_guard_is_denied_before_prepare() {
    assert_denied_before_prepare(GuardMode::Unavailable);
}
