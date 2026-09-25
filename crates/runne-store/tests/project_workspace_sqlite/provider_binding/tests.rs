use super::*;

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
    fixture
        .database
        .task_runs()
        .cancel_task_run(
            &task_context(0x49, "provider-binding-cancel"),
            CancelTaskRunInput {
                taskrun_id: fixture.identity.taskrun_id,
                expected_version: 4,
            },
        )
        .unwrap();
    assert_eq!(
        bind(&fixture, 4, fixture.prepared.clone()),
        Err(runne_application::ports::TaskRunProviderBindingError::StaleAssignment)
    );
}

#[test]
fn provider_binding_reopen_rejects_missing_claim_receipt() {
    let fixture = fixture("taskrun-provider-binding-missing-claim");
    bind(&fixture, 4, fixture.prepared.clone()).unwrap();
    let connection = fixture.database.connection();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER taskrun_claim_receipts_no_delete;")
        .unwrap();
    connection
        .execute(
            "DELETE FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![
                fixture.identity.taskrun_id.as_bytes(),
                fixture.identity.fence.0 as i64
            ],
        )
        .unwrap();
    connection.execute_batch("CREATE TRIGGER taskrun_claim_receipts_no_delete BEFORE DELETE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END;").unwrap();

    let rejected =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.database.reopen()));
    assert!(
        rejected.is_err(),
        "reopen admitted a binding without its claim receipt"
    );
}

#[test]
fn provider_binding_reopen_rejects_missing_dispatch_attempt() {
    let fixture = fixture("taskrun-provider-binding-missing-dispatch");
    bind(&fixture, 4, fixture.prepared.clone()).unwrap();
    let connection = fixture.database.connection();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute(
            "DELETE FROM provider_dispatch_attempts WHERE call_id=?1",
            [fixture.prepared.call_id.as_bytes()],
        )
        .unwrap();

    let rejected =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.database.reopen()));
    assert!(
        rejected.is_err(),
        "reopen admitted a binding without its dispatch attempt"
    );
}
