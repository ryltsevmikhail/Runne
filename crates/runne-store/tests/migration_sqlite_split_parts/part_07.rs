use rusqlite::params;

#[test]
fn same_command_rejects_stale_runne_receipt_scope_without_mutation() {
    let db = TempDb::new("stale-runne-receipt-same-command");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let context = stage_context();
    let fingerprint = fingerprint(1);
    store.commit(stage_commit()).unwrap();
    seed_stale_runne_receipt(&db.writer(), &context, &fingerprint);
    let before = receipt_snapshot(&db.reader());

    assert_eq!(
        store.lookup_receipt(&context, &fingerprint),
        Err(MigrationStoreError::IdempotencyConflict)
    );
    assert_eq!(receipt_snapshot(&db.reader()), before);
}

#[test]
fn different_command_colliding_with_stale_runne_scope_cannot_commit_effects() {
    let db = TempDb::new("stale-runne-receipt-different-command");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let original = stage_context();
    store.commit(stage_commit()).unwrap();
    seed_stale_runne_receipt(&db.writer(), &original, &fingerprint(1));
    let mut conflicting = command_context(2, 0, None);
    conflicting.idempotency_key = original.idempotency_key;
    let before = migration_durable_counts(&db.reader());

    assert_eq!(
        store.commit(stage_commit_with_context(conflicting)),
        Err(MigrationStoreError::IdempotencyConflict)
    );
    assert_eq!(migration_durable_counts(&db.reader()), before);
}

fn seed_stale_runne_receipt(
    connection: &Connection,
    context: &MigrationCommandContext,
    fingerprint: &MigrationCommandFingerprint,
) {
    let mut scope = b"runne-migration-scope\x01".to_vec();
    scope.extend_from_slice(&(context.operator_id.as_str().len() as u16).to_be_bytes());
    scope.extend_from_slice(context.operator_id.as_str().as_bytes());
    connection
        .execute(
            "UPDATE migration_receipts SET scope_bytes = ?1
             WHERE command_id = ?2 AND idempotency_key = ?3 AND fingerprint = ?4",
            params![
                scope,
                context.command_id.as_bytes().as_slice(),
                context.idempotency_key.as_str().as_bytes(),
                fingerprint.as_bytes().as_slice(),
            ],
        )
        .unwrap();
}

type ReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn receipt_snapshot(connection: &Connection) -> Vec<ReceiptRow> {
    connection
        .prepare(
            "SELECT command_id, scope_bytes, idempotency_key, fingerprint
             FROM migration_receipts ORDER BY command_id",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn stage_commit_with_context(context: MigrationCommandContext) -> MigrationCommit {
    let plan = test_plan();
    let snapshot = source_snapshot(RoutingGeneration::new(1).unwrap());
    let transition = transition("stale-scope-conflict", &plan);
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: Some(snapshot.clone()),
        transition_id: transition.transition_id.clone(),
    };
    let audit = audit(&context, &plan, MigrationAuditAction::StagePlan, 2);
    MigrationCommit::new(
        context,
        fingerprint(2),
        plan.clone(),
        vec![
            MigrationMutation::InsertPlan(plan),
            MigrationMutation::AppendTransition(transition),
            MigrationMutation::AppendRoutingSnapshot(snapshot),
        ],
        outcome,
        Some(audit),
    )
    .unwrap()
}
