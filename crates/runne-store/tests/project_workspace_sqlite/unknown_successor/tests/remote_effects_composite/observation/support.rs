use super::super::super::super::effect::Keyring;
use super::super::support::Fixture;
use runne_application::ports::{EventStore, RuntimeAuthorityId, TaskRunEffectsReadSnapshot};
use runne_application::provider::{
    ProviderRemoteFactAuthenticator, ProviderRemoteObservationProjection as Observation,
    ProviderRemoteRecoveryStore,
};
use runne_provider::{
    DispatchAttemptId, ProviderRecoveryBinding, ProviderRecoveryOperation, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderResponseIdentityCommitter, RemoteResponseId,
};
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;
use std::sync::Arc;

type Execution = runne_store::provider::SqliteProviderExecutionStore;
type Committer = RuntimeProviderRemoteIdentityCommitter<Keyring, Execution>;
pub(super) type EventFacts = Vec<([u8; 16], u64, [u8; 32])>;

pub(super) struct RemotePending {
    pub(super) fixture: Fixture,
    pub(super) attempt: DispatchAttemptId,
    recovery: ProviderRecoveryBinding,
    response_id: RemoteResponseId,
    pub(super) committer: Arc<Committer>,
}

pub(super) fn remote_pending(name: &str, tail: u8, response: &str) -> RemotePending {
    let fixture = super::super::super::super::fixture::running_with_remote_id(name, tail, response);
    let attempt = fixture
        .execution
        .find_remote_attempt(fixture.taskrun_id, fixture.claim_identity.attempt_id)
        .unwrap()
        .unwrap();
    let record = fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap();
    let binding = record.request.binding;
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        attempt,
        binding.profile_digest,
    )
    .unwrap();
    let committer = Arc::new(RuntimeProviderRemoteIdentityCommitter::new(
        Arc::new(Keyring),
        Arc::clone(&fixture.execution),
    ));
    RemotePending {
        fixture,
        attempt,
        recovery,
        response_id: RemoteResponseId::new(response).unwrap(),
        committer,
    }
}

pub(super) fn persist_status(prepared: &RemotePending, status: ProviderRemoteResponseStatus) {
    let record = prepared
        .fixture
        .execution
        .load_remote_attempt(prepared.attempt)
        .unwrap()
        .unwrap();
    let proof = prepared
        .fixture
        .execution
        .issue_remote_operation_proof(
            &record.request.binding,
            &prepared.response_id,
            ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap();
    let check = ProviderRemoteCheck::new_authorized(
        prepared.recovery,
        prepared.response_id.clone(),
        status,
        None,
        ProviderRecoveryOperation::StatusCheck,
        proof,
    )
    .unwrap();
    futures::executor::block_on(prepared.committer.persist_remote_check(&check)).unwrap();
}

pub(super) fn issue_status_proof(
    prepared: &RemotePending,
) -> runne_provider::ProviderRemoteOperationProof {
    let record = prepared
        .fixture
        .execution
        .load_remote_attempt(prepared.attempt)
        .unwrap()
        .unwrap();
    prepared
        .fixture
        .execution
        .issue_remote_operation_proof(
            &record.request.binding,
            &prepared.response_id,
            ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap()
}

pub(super) fn read(prepared: &RemotePending) -> TaskRunEffectsReadSnapshot {
    prepared
        .fixture
        .database
        .store
        .load_task_run_effects_with_remote_authenticator(
            prepared.fixture.taskrun_id,
            Some(prepared.committer.as_ref() as &dyn ProviderRemoteFactAuthenticator),
            Some(&super::super::super::Resolver),
        )
        .unwrap()
}

pub(super) fn read_reopened(prepared: &RemotePending) -> TaskRunEffectsReadSnapshot {
    let store = crate::validated_reopen::reopen_store(
        prepared.fixture.database.file.path(),
        prepared.fixture.database.identity,
        RuntimeAuthorityId("01010101010101010101010101010101".into()),
        super::super::super::guard(),
    )
    .unwrap();
    let execution = Arc::new(
        crate::validated_reopen::open_provider_execution(
            prepared.fixture.database.file.path(),
            prepared.fixture.database.identity,
        )
        .unwrap(),
    );
    let committer = RuntimeProviderRemoteIdentityCommitter::new(Arc::new(Keyring), execution);
    store
        .load_task_run_effects_with_remote_authenticator(
            prepared.fixture.taskrun_id,
            Some(&committer),
            Some(&super::super::super::Resolver),
        )
        .unwrap()
}

pub(super) fn history(fixture: &Fixture) -> (u64, EventFacts) {
    let stream = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    let events = stream
        .events
        .iter()
        .map(|event| {
            (
                *event.event_id().as_bytes(),
                event.sequence(),
                *event.integrity_digest().as_bytes(),
            )
        })
        .collect();
    (stream.current_version, events)
}

pub(super) fn durable_counts(fixture: &Fixture, attempt: DispatchAttemptId) -> (i64, i64, i64) {
    fixture
        .database
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_remote_request_intents WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM provider_dispatch_attempts WHERE attempt_id=?2),
                    (SELECT COUNT(*) FROM provider_remote_operation_proofs WHERE dispatch_attempt_id=?3)",
            rusqlite::params![
                fixture.taskrun_id.as_bytes().as_slice(),
                attempt.as_bytes().as_slice(),
                attempt.as_bytes().as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

pub(super) fn assert_unknown(snapshot: &TaskRunEffectsReadSnapshot, fixture: &Fixture) {
    assert_eq!(snapshot.effects.taskrun_id, fixture.taskrun_id);
    assert_eq!(
        snapshot.effects.attempt_id,
        Some(fixture.claim_identity.attempt_id)
    );
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Unknown
    );
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Unknown
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Unknown
    );
    assert_eq!(snapshot.effects.remote.usage_known, None);
}

pub(super) fn assert_pending(
    snapshot: &TaskRunEffectsReadSnapshot,
    fixture: &Fixture,
    cancel: bool,
) {
    assert_eq!(snapshot.effects.taskrun_id, fixture.taskrun_id);
    assert_eq!(
        snapshot.effects.attempt_id,
        Some(fixture.claim_identity.attempt_id)
    );
    let remote = snapshot.remote.as_ref().expect("validated remote attempt");
    assert!(remote.fact.is_none(), "Pending is not a terminal fact");
    assert_eq!(remote.observation, Observation::Pending);
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Running
    );
    assert_eq!(
        snapshot.effects.remote.cancellation,
        if cancel {
            runne_api::RemoteCancellationV1::Unconfirmed
        } else {
            runne_api::RemoteCancellationV1::NotRequested
        }
    );
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Unknown
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Unknown
    );
    assert_eq!(snapshot.effects.remote.usage_known, None);
}
