use std::path::Path;

use super::*;

pub(super) async fn run(
    database: &Path,
    task_bytes: [u8; 16],
    store: &runne_store::store::StoreTransaction,
    runtime_authority_id: runne_application::ports::RuntimeAuthorityId,
    node_id: [u8; 16],
    node_epoch: i64,
    terminal_version: u64,
) {
    let taskrun_domain_id = runne_domain::id::TaskRunId::from_bytes(task_bytes);
    let effects_before =
        runne_application::ports::EventStore::load_task_run_effects(store, taskrun_domain_id)
            .expect("read recovered effects through the reopened store");
    let before_connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open post-shutdown native claim baseline reader");
    let before = native_unknown_fresh_claim_snapshot(
        &before_connection,
        task_bytes.as_slice(),
        effects_before,
    )
    .expect("snapshot recovered state before fresh claim");
    drop(before_connection);
    assert_eq!(before.local_attempts.len(), 1);
    assert_eq!(before.stop_receipts.len(), 1);
    assert_eq!(before.terminal_receipts.len(), 1);
    assert_eq!(before.assignment_occupations.len(), 1);
    assert_eq!(before.claim_receipts.len(), 1);
    assert_eq!(before.effects.stream_version, terminal_version);
    assert_eq!(
        before.effects.local_command.as_ref().map(|local| (
            local.outcome,
            local.stop,
            local.exit_code
        )),
        Some((
            runne_api::LocalCommandOutcomeV1::OutcomeUnknown,
            runne_api::LocalCommandStopV1::Confirmed,
            None
        )),
        "reopened effects retain unknown outcome and confirmed stop"
    );

    let command_uuid = uuid::Uuid::now_v7();
    // DaemonAutomaticTaskRuns::runtime_context uses this runtime principal and actor.
    let claim_context = runne_application::ports::ApplicationCommandContext {
        command_id: runne_domain::id::CommandId::from_bytes(*command_uuid.as_bytes()),
        idempotency_key: runne_domain::id::IdempotencyKey::new(format!(
            "native-unknown-fresh-claim-{command_uuid}"
        ))
        .expect("fresh native claim idempotency key"),
        principal_id: runne_application::ports::PrincipalId("runne-runtime".into()),
        actor: runne_domain::event::Actor::new("runne-runtime")
            .expect("built-in runtime actor identity"),
    };
    let claim_port = FreshClaimReadOnlyPort {
        store,
        lookups: std::cell::Cell::new(0),
    };
    let service = runne_application::service::TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        runtime_authority_id,
    );
    let claim_result = service.claim_task_run(
        &claim_context,
        runne_application::service::ClaimTaskRunInput {
            taskrun_id: taskrun_domain_id,
            expected_version: terminal_version,
            node_id: runne_application::ports::ExecutionNodeId(
                uuid::Uuid::from_bytes(node_id).to_string(),
            ),
            node_epoch: u64::try_from(node_epoch).expect("current node epoch is positive"),
            capability_descriptor: "linux-executor-v1".into(),
            lease_duration_ms: 300_000,
        },
        &claim_port,
    );
    assert_eq!(
        claim_result,
        Err(runne_application::service::ClaimTaskRunServiceError::NotQueued),
        "a fresh canonical claim retry rejects the recovered terminal TaskRun"
    );
    assert_eq!(
        claim_port.lookups.get(),
        2,
        "the service performed both read-only receipt lookups"
    );
    let effects_after =
        runne_application::ports::EventStore::load_task_run_effects(store, taskrun_domain_id)
            .expect("read recovered effects after fresh claim rejection");
    let after_connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open post-claim native state reader");
    let after = native_unknown_fresh_claim_snapshot(
        &after_connection,
        task_bytes.as_slice(),
        effects_after,
    )
    .expect("snapshot recovered state after fresh claim");
    assert_eq!(after, before, "fresh claim rejection appended no state");
    eprintln!("PASS: protected local-command daemon crash and restart recovery");
}
