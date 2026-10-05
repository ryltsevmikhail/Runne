use runne_runtime_client::{AuthenticatedRuntimeClient, CanonicalId, TaskRunState};

pub async fn assert_forged_claim_history_is_rejected(
    client: &AuthenticatedRuntimeClient,
    database: &std::path::Path,
    task: CanonicalId,
) {
    use runne_application::ports::{
        AggregateScope, IdempotencyScope, OperationTag, PrincipalId, RuntimeAuthorityId,
    };
    use runne_store::codec::{IdempotencyScopeCodec, StoreCodec};

    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db = rusqlite::Connection::open(database).expect("open isolated fixture database");
    assert_effects_available(client, task).await;
    let scope_bytes: Vec<u8> = db
        .query_row(
            "SELECT idempotency_scope_bytes FROM taskrun_claim_receipts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("read exact runtime claim scope");
    let forged_scope = IdempotencyScope {
        runtime_authority_id: RuntimeAuthorityId("forged-authority".into()),
        principal_id: PrincipalId("runne-runtime".into()),
        operation: OperationTag::TaskRunClaim,
        aggregate_scope: AggregateScope::ExistingTaskRun {
            taskrun_id: runne_domain::id::TaskRunId::from_bytes(task_bytes),
        },
    };
    let forged_scope_bytes = IdempotencyScopeCodec
        .encode(&forged_scope)
        .expect("encode well-formed forged claim scope");
    tamper_triggered(
        &db,
        "taskrun_claim_receipts_immutable",
        "CREATE TRIGGER taskrun_claim_receipts_immutable BEFORE UPDATE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END",
        "UPDATE taskrun_claim_receipts SET idempotency_scope_bytes=?1 WHERE taskrun_id=?2",
        rusqlite::params![forged_scope_bytes, task_bytes.as_slice()],
    );
    assert_taskrun_readable(client, task).await;
    assert_effects_unavailable(client, task).await;
    tamper_triggered(
        &db,
        "taskrun_claim_receipts_immutable",
        "CREATE TRIGGER taskrun_claim_receipts_immutable BEFORE UPDATE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END",
        "UPDATE taskrun_claim_receipts SET idempotency_scope_bytes=?1 WHERE taskrun_id=?2",
        rusqlite::params![scope_bytes, task_bytes.as_slice()],
    );
    assert_effects_available(client, task).await;

    let (fence, epoch): (i64, i64) = db
        .query_row(
            "SELECT fence,node_epoch FROM taskrun_claim_receipts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read exact assignment identity");
    assert_effects_available(client, task).await;
    tamper_triggered(
        &db,
        "taskrun_assignments_immutable",
        "CREATE TRIGGER taskrun_assignments_immutable BEFORE UPDATE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END",
        "UPDATE taskrun_assignments SET node_epoch=?1 WHERE taskrun_id=?2 AND fence=?3",
        rusqlite::params![epoch + 1, task_bytes.as_slice(), fence],
    );
    assert_taskrun_readable(client, task).await;
    assert_effects_unavailable(client, task).await;
    tamper_triggered(
        &db,
        "taskrun_assignments_immutable",
        "CREATE TRIGGER taskrun_assignments_immutable BEFORE UPDATE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END",
        "UPDATE taskrun_assignments SET node_epoch=?1 WHERE taskrun_id=?2 AND fence=?3",
        rusqlite::params![epoch, task_bytes.as_slice(), fence],
    );
    assert_effects_available(client, task).await;
}

fn tamper_triggered<P: rusqlite::Params>(
    db: &rusqlite::Connection,
    trigger: &str,
    restore_trigger_sql: &str,
    update: &str,
    params: P,
) {
    db.execute_batch(&format!("DROP TRIGGER {trigger}"))
        .expect("temporarily remove immutable test trigger");
    assert_eq!(
        db.execute(update, params)
            .expect("mutate exact fixture receipt"),
        1
    );
    db.execute_batch(restore_trigger_sql)
        .expect("restore immutable test trigger");
}

async fn assert_effects_unavailable(client: &AuthenticatedRuntimeClient, task: CanonicalId) {
    let error = client
        .get_task_run_effects(task)
        .await
        .expect_err("forged runtime claim history must fail closed");
    assert_eq!(
        error.kind(),
        runne_runtime_client::RuntimeApiErrorKind::Unavailable
    );
}

async fn assert_effects_available(client: &AuthenticatedRuntimeClient, task: CanonicalId) {
    client
        .get_task_run_effects(task)
        .await
        .expect("restored fixture claim history is available");
}

async fn assert_taskrun_readable(client: &AuthenticatedRuntimeClient, task: CanonicalId) {
    assert_eq!(
        client
            .get_task_run(task)
            .await
            .expect("TaskRun endpoint remains live during effects rejection")
            .state(),
        TaskRunState::Cancelled
    );
}
