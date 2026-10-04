use super::*;
use runne_store::codec::{StoreCodec, TaskRunEventCodec};

#[test]
fn provider_binding_commits_intent_and_replays_exact_identity() {
    let fixture = fixture("taskrun-provider-binding-exact");
    assert_eq!(
        bind(&fixture, 4, fixture.prepared.clone()).unwrap(),
        TaskRunProviderBindingResult::Bound
    );
    assert_eq!(
        bind(&fixture, 4, fixture.prepared.clone()).unwrap(),
        TaskRunProviderBindingResult::Duplicate
    );
    let _reopened = fixture.database.reopen();
    let connection = fixture.database.connection();
    let (bindings, intents, occupation): (i64,i64,String) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2),(SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2),(SELECT dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2)",
        rusqlite::params![fixture.identity.taskrun_id.as_bytes(),fixture.identity.fence.0 as i64],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).unwrap();
    assert_eq!((bindings, intents, occupation.as_str()), (1, 1, "present"));
    assert!(connection.execute(
        "UPDATE taskrun_provider_bindings SET prepared_digest=zeroblob(32) WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![fixture.identity.taskrun_id.as_bytes(), fixture.identity.fence.0 as i64],
    ).is_err());
    assert!(
        connection
            .execute(
                "DELETE FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2",
                rusqlite::params![
                    fixture.identity.taskrun_id.as_bytes(),
                    fixture.identity.fence.0 as i64
                ],
            )
            .is_err()
    );
}

#[test]
fn provider_binding_rolls_back_intent_when_binding_insert_fails() {
    let fixture = fixture("taskrun-provider-binding-atomic");
    fixture.database.connection().execute_batch(
        "CREATE TRIGGER fail_taskrun_provider_binding BEFORE INSERT ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'injected binding failure'); END",
    ).unwrap();
    assert_eq!(
        bind(&fixture, 4, fixture.prepared.clone()),
        Err(runne_application::ports::TaskRunProviderBindingError::CorruptData)
    );
    let connection = fixture.database.connection();
    let (bindings,intents,occupation): (i64,i64,String) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2),(SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2),(SELECT dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2)",
        rusqlite::params![fixture.identity.taskrun_id.as_bytes(),fixture.identity.fence.0 as i64],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).unwrap();
    assert_eq!((bindings, intents, occupation.as_str()), (0, 0, "absent"));
}

#[test]
fn provider_binding_rejects_existing_unbound_dispatch_intent() {
    let fixture = fixture("taskrun-provider-binding-existing-intent");
    assert_eq!(
        fixture
            .database
            .store
            .prepare_taskrun_dispatch(fixture.identity.clone())
            .unwrap(),
        runne_application::ports::TaskRunDispatchIntentResult::Prepared
    );

    assert_eq!(
        bind(&fixture, 4, fixture.prepared.clone()),
        Err(runne_application::ports::TaskRunProviderBindingError::StaleAssignment)
    );
    let connection = fixture.database.connection();
    let (bindings, intents, occupation): (i64, i64, String) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2),(SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2),(SELECT dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2)",
            rusqlite::params![fixture.identity.taskrun_id.as_bytes(), fixture.identity.fence.0 as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((bindings, intents, occupation.as_str()), (0, 1, "present"));
}

#[test]
fn provider_binding_rejects_changed_metadata_and_stale_fences() {
    let fixture = fixture("taskrun-provider-binding-conflicts");
    bind(&fixture, 4, fixture.prepared.clone()).unwrap();
    let mut changed_digest = fixture.prepared.clone();
    changed_digest.prepared_digest[0] ^= 1;
    assert_eq!(
        bind(&fixture, 4, changed_digest),
        Err(runne_application::ports::TaskRunProviderBindingError::IdempotencyConflict)
    );
    let mut changed_key = fixture.prepared.clone();
    changed_key.provider_idempotency_key.push_str("-changed");
    assert_eq!(
        bind(&fixture, 4, changed_key),
        Err(runne_application::ports::TaskRunProviderBindingError::IdempotencyConflict)
    );
    let stale_fence = TaskRunAssignmentIdentity {
        fence: runne_application::ports::TaskRunFence(fixture.identity.fence.0 + 1),
        ..fixture.identity.clone()
    };
    assert_eq!(
        fixture
            .database
            .store
            .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
                identity: stale_fence,
                expected_claim_version: 4,
                prepared: fixture.prepared.clone()
            }),
        Err(runne_application::ports::TaskRunProviderBindingError::StaleAssignment)
    );
}

#[test]
fn provider_binding_rejects_stale_version_epoch_expiry_and_cancel() {
    let fixture = fixture("taskrun-provider-binding-fences");
    assert_eq!(
        bind(&fixture, 3, fixture.prepared.clone()),
        Err(runne_application::ports::TaskRunProviderBindingError::StaleVersion)
    );
    let stale_epoch = TaskRunAssignmentIdentity {
        node_epoch: fixture.identity.node_epoch + 1,
        ..fixture.identity.clone()
    };
    assert_eq!(
        fixture
            .database
            .store
            .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
                identity: stale_epoch,
                expected_claim_version: 4,
                prepared: fixture.prepared.clone()
            }),
        Err(runne_application::ports::TaskRunProviderBindingError::StaleAssignment)
    );
    let connection = fixture.database.connection();
    connection.execute("UPDATE taskrun_assignment_occupations SET lease_expires_at_ms=1 WHERE taskrun_id=?1 AND fence=?2", rusqlite::params![fixture.identity.taskrun_id.as_bytes(),fixture.identity.fence.0 as i64]).unwrap();
    assert_eq!(
        bind(&fixture, 4, fixture.prepared.clone()),
        Err(runne_application::ports::TaskRunProviderBindingError::LeaseExpired)
    );
    // Restore a live lease for the cancellation check while preserving the claim receipt.
    connection.execute("UPDATE taskrun_assignment_occupations SET lease_expires_at_ms=(SELECT lease_expires_at_ms FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2) WHERE taskrun_id=?1 AND fence=?2", rusqlite::params![fixture.identity.taskrun_id.as_bytes(),fixture.identity.fence.0 as i64]).unwrap();
    let cancellation_context = task_context(0x49, "provider-binding-cancel");
    fixture
        .database
        .task_runs()
        .cancel_task_run(
            &cancellation_context,
            CancelTaskRunInput {
                taskrun_id: fixture.identity.taskrun_id,
                expected_version: 4,
            },
        )
        .unwrap();
    let connection = fixture.database.connection();
    let (fenced_taskrun, fenced_attempt, fenced_dispatch, cancellation_event, cancellation_version):
        (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) = connection
            .query_row(
                "SELECT taskrun_id,taskrun_attempt_id,dispatch_attempt_id,cancellation_event_id,cancellation_version
                 FROM taskrun_provider_cancel_fences WHERE taskrun_id=?1",
                [fixture.identity.taskrun_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
    let expected_dispatch: Vec<u8> = connection
        .query_row(
            "SELECT dispatch_attempt_id FROM provider_execution_admissions
             WHERE taskrun_id=?1 AND execution_attempt_id=?2",
            rusqlite::params![
                fixture.identity.taskrun_id.as_bytes(),
                fixture.identity.attempt_id.as_bytes()
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fenced_taskrun, fixture.identity.taskrun_id.as_bytes());
    assert_eq!(fenced_attempt, fixture.identity.attempt_id.as_bytes());
    assert_ne!(fenced_attempt, [0x99; 16]);
    assert_eq!(fenced_dispatch, expected_dispatch);
    assert_eq!(cancellation_version, 5);
    let cancellation_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE event_id=?1 AND aggregate_id=?2 AND sequence=?3",
            rusqlite::params![
                cancellation_event,
                fixture.identity.taskrun_id.as_bytes(),
                cancellation_version
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        TaskRunEventCodec.decode(&cancellation_payload).unwrap(),
        runne_domain::task_run::TaskRunEvent::CancellationRequested
    );
    fixture
        .database
        .task_runs()
        .cancel_task_run(
            &cancellation_context,
            CancelTaskRunInput {
                taskrun_id: fixture.identity.taskrun_id,
                expected_version: 4,
            },
        )
        .unwrap();
    let fence_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_provider_cancel_fences WHERE taskrun_id=?1",
            [fixture.identity.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        fence_count, 1,
        "exact command replay cannot append another fence"
    );
    let before_repeated_cancel: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE aggregate_id=?1",
            [fixture.identity.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(matches!(
        fixture.database.task_runs().cancel_task_run(
            &task_context(0x4a, "provider-binding-cancel-again"),
            CancelTaskRunInput {
                taskrun_id: fixture.identity.taskrun_id,
                expected_version: 5,
            },
        ),
        Err(runne_application::errors::ApplicationError::Domain(
            runne_domain::error::DomainError::InvalidTransition {
                from: runne_domain::task_run::TaskRunState::Cancelling,
                event: runne_domain::task_run::TaskRunEventKind::CancellationRequested,
            }
        ))
    ));
    let after_repeated_cancel: (i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM events WHERE aggregate_id=?1),
                    (SELECT COUNT(*) FROM taskrun_provider_cancel_fences WHERE taskrun_id=?1),
                    (SELECT current_version FROM aggregate_streams
                     WHERE aggregate_type=1 AND aggregate_id=?1)",
            [fixture.identity.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(after_repeated_cancel, (before_repeated_cancel, 1, 5));
    assert_eq!(
        bind(&fixture, 4, fixture.prepared.clone()),
        Err(runne_application::ports::TaskRunProviderBindingError::StaleAssignment)
    );
}

mod reopen_integrity;
