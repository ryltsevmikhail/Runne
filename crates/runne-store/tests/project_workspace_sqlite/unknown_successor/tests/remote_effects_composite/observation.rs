#[path = "observation/support.rs"]
mod support;

use runne_application::commands::CancelTaskRunInput;
use runne_application::ports::{EventStore, RuntimeAuthorityId};
use runne_application::provider::{
    ProviderRemoteObservationProjection as Observation, ProviderRemoteRecoveryStore,
};
use runne_application::service::TaskRunService;
use runne_provider::{DispatchAttemptId, ProviderRemoteResponseStatus};
use support::*;

#[test]
fn passive_effects_use_only_fresh_pending_observations_without_writes() {
    let prepared = remote_pending("effects-pending-observation", 0x9a, "resp_effects_pending");
    let original_history = history(&prepared.fixture);
    let initial_counts = durable_counts(&prepared.fixture, prepared.attempt);
    let initial = read(&prepared);
    assert_unknown(&initial, &prepared.fixture);
    assert_eq!(
        initial.effects.remote.cancellation,
        runne_api::RemoteCancellationV1::NotRequested
    );
    assert_eq!(
        initial.remote.as_ref().unwrap().observation,
        Observation::NotObserved
    );
    assert_eq!(history(&prepared.fixture), original_history);
    assert_eq!(
        durable_counts(&prepared.fixture, prepared.attempt),
        initial_counts
    );

    persist_status(&prepared, ProviderRemoteResponseStatus::Pending);
    let pending_counts = durable_counts(&prepared.fixture, prepared.attempt);
    let pending_history = history(&prepared.fixture);
    let pending = read(&prepared);
    assert_pending(&pending, &prepared.fixture, false);
    assert_eq!(pending.effects.stream_version, prepared.fixture.version);
    assert_eq!(history(&prepared.fixture), pending_history);
    assert_eq!(
        durable_counts(&prepared.fixture, prepared.attempt),
        pending_counts
    );

    let outstanding = issue_status_proof(&prepared);
    let outstanding_counts = durable_counts(&prepared.fixture, prepared.attempt);
    let backed_by_pending = read(&prepared);
    assert_pending(&backed_by_pending, &prepared.fixture, false);
    assert_eq!(history(&prepared.fixture), pending_history);
    assert_eq!(
        durable_counts(&prepared.fixture, prepared.attempt),
        outstanding_counts
    );
    assert_pending(&read_reopened(&prepared), &prepared.fixture, false);

    prepared
        .fixture
        .execution
        .commit_remote_operation_observation(&outstanding, ProviderRemoteResponseStatus::Unknown)
        .unwrap();
    let without_fresh_pending = issue_status_proof(&prepared);
    let unknown_counts = durable_counts(&prepared.fixture, prepared.attempt);
    let unknown = read(&prepared);
    assert_unknown(&unknown, &prepared.fixture);
    assert_eq!(
        unknown.remote.as_ref().unwrap().observation,
        Observation::Unknown
    );
    assert_eq!(history(&prepared.fixture), pending_history);
    assert_eq!(
        durable_counts(&prepared.fixture, prepared.attempt),
        unknown_counts
    );
    prepared
        .fixture
        .execution
        .commit_remote_operation_observation(
            &without_fresh_pending,
            ProviderRemoteResponseStatus::Unknown,
        )
        .unwrap();
    assert_unknown(&read_reopened(&prepared), &prepared.fixture);
    assert_eq!(history(&prepared.fixture), pending_history);
    assert_eq!(
        durable_counts(&prepared.fixture, prepared.attempt),
        unknown_counts
    );
}

#[test]
fn accepted_cancellation_without_remote_terminal_is_unconfirmed_with_or_without_snapshot() {
    let prepared = remote_pending(
        "effects-pending-cancel",
        0x9b,
        "resp_effects_pending_cancel",
    );
    persist_status(&prepared, ProviderRemoteResponseStatus::Pending);
    TaskRunService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        RuntimeAuthorityId("01010101010101010101010101010101".into()),
    )
    .cancel_task_run(
        &super::super::context(0xec, "effects-pending-cancel"),
        CancelTaskRunInput {
            taskrun_id: prepared.fixture.taskrun_id,
            expected_version: prepared.fixture.version,
        },
    )
    .unwrap();
    let cancel_history = history(&prepared.fixture);
    let cancel_counts = durable_counts(&prepared.fixture, prepared.attempt);
    let cancelled = read(&prepared);
    assert_pending(&cancelled, &prepared.fixture, true);
    assert_eq!(
        cancelled.effects.stream_version,
        prepared.fixture.version + 1
    );
    assert_eq!(history(&prepared.fixture), cancel_history);
    assert_eq!(
        durable_counts(&prepared.fixture, prepared.attempt),
        cancel_counts
    );
    assert_pending(&read_reopened(&prepared), &prepared.fixture, true);

    let no_remote = super::super::super::fixture::running_without_provider_admission(
        "effects-cancel-no-remote-snapshot",
        0x9d,
    );
    let no_remote_attempt = DispatchAttemptId::from_bytes([0; 16]);
    let no_remote_counts = durable_counts(&no_remote, no_remote_attempt);
    let before = no_remote
        .database
        .store
        .load_task_run_effects_with_remote_authenticator(
            no_remote.taskrun_id,
            None,
            Some(&super::super::Resolver),
        )
        .unwrap();
    assert!(before.remote.is_none());
    assert_unknown(&before, &no_remote);
    assert_eq!(
        before.effects.remote.cancellation,
        runne_api::RemoteCancellationV1::NotRequested
    );
    TaskRunService::new(
        no_remote.database.store.clone(),
        no_remote.database.store.clone(),
        no_remote.database.store.clone(),
        RuntimeAuthorityId("01010101010101010101010101010101".into()),
    )
    .cancel_task_run(
        &super::super::context(0xee, "effects-cancel-no-remote-snapshot"),
        CancelTaskRunInput {
            taskrun_id: no_remote.taskrun_id,
            expected_version: no_remote.version,
        },
    )
    .unwrap();
    let after = no_remote
        .database
        .store
        .load_task_run_effects_with_remote_authenticator(
            no_remote.taskrun_id,
            None,
            Some(&super::super::Resolver),
        )
        .unwrap();
    assert!(after.remote.is_none());
    assert_eq!(
        after.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Unknown
    );
    assert_eq!(
        after.effects.remote.cancellation,
        runne_api::RemoteCancellationV1::Unconfirmed
    );
    assert_eq!(after.effects.stream_version, no_remote.version + 1);
    let no_remote_history = history(&no_remote);
    assert_eq!(
        durable_counts(&no_remote, no_remote_attempt),
        no_remote_counts,
    );
    let reopened = crate::validated_reopen::reopen_store(
        no_remote.database.file.path(),
        no_remote.database.identity,
        RuntimeAuthorityId("01010101010101010101010101010101".into()),
        super::super::guard(),
    )
    .unwrap();
    let reopened_effects = reopened
        .load_task_run_effects_with_remote_authenticator(
            no_remote.taskrun_id,
            None,
            Some(&super::super::Resolver),
        )
        .unwrap();
    assert_eq!(reopened_effects, after);
    assert_eq!(history(&no_remote), no_remote_history);
}
