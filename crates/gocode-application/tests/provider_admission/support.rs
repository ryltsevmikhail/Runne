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
    DispatchAttemptId, ModelRef, PreparedProviderRecord, ProviderCall, ProviderCallId,
    ProviderCapability, ProviderDispatchClaim, ProviderDispatchRepository, ProviderId,
    ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderRepositoryState,
    ProviderStreamEvent, ProviderStreamEventKind, ScriptedProvider,
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
        render_digest: [3; 32],
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
    let _ = ProviderEffectRequest {
        authority_ref: request.authority_ref,
        attempt_id: request.attempt_id,
        permit_id: request.permit_id,
        prepared_digest: [2; 32],
        render_digest: request.render_digest,
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
    prepared_count: Mutex<usize>,
    claim_count: Mutex<usize>,
    streaming_count: Mutex<usize>,
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

    fn record_streaming(&self) {
        *self.streaming_count.lock().unwrap() += 1;
    }
}

impl ProviderDispatchRepository for RecordingRepository {
    fn persist_prepared(
        &self,
        _record: &PreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        *self.prepared_count.lock().unwrap() += 1;
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
