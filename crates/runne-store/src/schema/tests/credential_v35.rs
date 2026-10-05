fn seed_v35_ticket(connection: &Connection, operation: u8, attempt: i64) {
    let provider = format!("qualification-{operation}");
    connection.execute(
        "INSERT INTO provider_credential_authority_heads
         (provider_id,lifecycle_revision,credential_fence,readiness_revision,next_credential_version)
         VALUES (?1,1,1,1,1)",
        [&provider],
    ).unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_operations
         (operation_id,installation_owner_id,provider_id,action,command_id,idempotency_key,
          expected_lifecycle_revision,expected_credential_fence,allocated_credential_version,
          allocated_ref_digest,state,begin_proof_digest,begin_proof_expires_at_high_water,
          qualified_release_tuple_digest,created_at,updated_at)
         VALUES (?1,?2,?3,'PAIR',?1,?4,1,1,1,?5,'PREPARED',?6,300,?7,1,1)",
            params![
                [operation; 16],
                [operation; 32],
                provider,
                format!("qualification-op-{operation}"),
                [operation.wrapping_add(1); 32],
                [operation.wrapping_add(2); 32],
                [operation.wrapping_add(3); 32],
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_process_attachments
         (operation_id,attachment_attempt,continuation_binding_digest,attached_at,state)
         VALUES (?1,1,?2,100,'ATTACHED')",
            params![[operation; 16], [operation.wrapping_add(4); 32]],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_ticket_attempts
         (operation_id,attempt,ticket_digest,continuation_binding_digest,issued_at,expires_at,state)
         VALUES (?1,?2,?3,?4,110,190,'ISSUED')",
            params![
                [operation; 16],
                attempt,
                [operation.wrapping_add(5); 32],
                [operation.wrapping_add(4); 32],
            ],
        )
        .unwrap();
}

struct V35FenceInsert<'a> {
    operation: u8,
    attempt: i64,
    seed: u8,
    replay_ids: [[u8; 32]; 4],
    selector: &'a str,
    role: &'a str,
    workflow: &'a str,
    context_times: (i64, i64),
    ticket_times: (i64, i64),
    session: [u8; 32],
    generations: (i64, i64, i64),
    verified_at: i64,
    committed_at: i64,
}

impl V35FenceInsert<'_> {
    fn valid(operation: u8, seed: u8) -> V35FenceInsert<'static> {
        V35FenceInsert {
            operation,
            attempt: 1,
            seed,
            replay_ids: [
                [seed; 32],
                [seed.wrapping_add(1); 32],
                [seed.wrapping_add(2); 32],
                [seed.wrapping_add(3); 32],
            ],
            selector: "kill_before_native_effect",
            role: "service",
            workflow: "run-42",
            context_times: (100, 180),
            ticket_times: (100, 185),
            session: [seed.wrapping_add(9); 32],
            generations: (1, 2, 3),
            verified_at: 120,
            committed_at: 130,
        }
    }
}

fn insert_v35_fence(connection: &Connection, value: &V35FenceInsert<'_>) -> SqliteResult<usize> {
    write_v35_fence(connection, value, "INSERT")
}

fn replace_v35_fence(connection: &Connection, value: &V35FenceInsert<'_>) -> SqliteResult<usize> {
    write_v35_fence(connection, value, "INSERT OR REPLACE")
}

fn write_v35_fence(
    connection: &Connection,
    value: &V35FenceInsert<'_>,
    insert: &str,
) -> SqliteResult<usize> {
    let seed = value.seed;
    connection.execute(
        &format!(
            "{insert} INTO provider_qualification_admission_fences
         (operation_id,attempt,context_id,context_nonce,ticket_id,ticket_nonce,ticket_sha256,
          scenario_id,selector,process_role,candidate_sha256,raw_v3_tuple_sha256,source_revision,
          workflow_run_id,namespace_sha256,context_issued_at,context_expires_at,ticket_issued_at,
          ticket_expires_at,protected_session_digest,runtime_authority_id,database_generation,
          launch_generation,supervisor_generation,verified_at,committed_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,'macos-xpc-dpk-v1',?8,?9,?10,?11,?12,?13,?14,
                 ?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)"
        ),
        params![
            [value.operation; 16],
            value.attempt,
            value.replay_ids[0],
            value.replay_ids[1],
            value.replay_ids[2],
            value.replay_ids[3],
            [seed.wrapping_add(4); 32],
            value.selector,
            value.role,
            [seed.wrapping_add(5); 32],
            [seed.wrapping_add(6); 32],
            [seed.wrapping_add(7); 20],
            value.workflow,
            [seed.wrapping_add(8); 32],
            value.context_times.0,
            value.context_times.1,
            value.ticket_times.0,
            value.ticket_times.1,
            value.session,
            [seed.wrapping_add(10); 16],
            value.generations.0,
            value.generations.1,
            value.generations.2,
            value.verified_at,
            value.committed_at,
        ],
    )
}

#[test]
fn v35_creates_reopens_and_upgrades_from_v34() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("qualification-v35.sqlite")
    };
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 34).unwrap();
    assert!(v34_matches(&connection, 34).unwrap());
    apply_migrations(&connection).unwrap();
    assert_eq!(CURRENT_SCHEMA_VERSION, 64);
    assert!(v64_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap());
    drop(connection);
    drop(open_managed_connection(&path, ConnectionMode::Writer).unwrap());
}

#[test]
fn v35_fence_is_unique_append_only_and_binds_an_issued_attempt() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    seed_v35_ticket(&connection, 31, 1);
    insert_v35_fence(&connection, &V35FenceInsert::valid(31, 40)).unwrap();
    assert!(insert_v35_fence(&connection, &V35FenceInsert::valid(31, 60)).is_err());
    assert!(
        connection
            .execute(
                "UPDATE provider_qualification_admission_fences SET committed_at=131",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM provider_qualification_admission_fences", [],)
            .is_err()
    );

    seed_v35_ticket(&connection, 32, 1);
    connection
        .execute(
            "UPDATE provider_credential_ticket_attempts SET state='EXPIRED'
         WHERE operation_id=?1 AND attempt=1",
            [[32_u8; 16]],
        )
        .unwrap();
    assert!(insert_v35_fence(&connection, &V35FenceInsert::valid(32, 80)).is_err());

    seed_v35_ticket(&connection, 33, 1);
    let mut wrong_attempt = V35FenceInsert::valid(33, 90);
    wrong_attempt.attempt = 2;
    assert!(insert_v35_fence(&connection, &wrong_attempt).is_err());
}

#[test]
fn v35_rejects_replay_role_session_generation_and_expiry_edges() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    seed_v35_ticket(&connection, 40, 1);
    insert_v35_fence(&connection, &V35FenceInsert::valid(40, 100)).unwrap();

    let mut operation = 41;
    let mut reject = |mut value: V35FenceInsert<'_>| {
        seed_v35_ticket(&connection, operation, 1);
        value.operation = operation;
        operation += 1;
        assert!(insert_v35_fence(&connection, &value).is_err());
    };
    reject(V35FenceInsert::valid(0, 100));
    let mut bad = V35FenceInsert::valid(0, 120);
    bad.role = "runtime";
    reject(bad);
    let mut bad = V35FenceInsert::valid(0, 130);
    bad.workflow = "run-42\0hidden";
    reject(bad);
    let mut bad = V35FenceInsert::valid(0, 140);
    bad.session = [0; 32];
    reject(bad);
    let mut bad = V35FenceInsert::valid(0, 150);
    bad.generations = (1, 0, 3);
    reject(bad);
    let mut bad = V35FenceInsert::valid(0, 160);
    bad.context_times = (100, 1001);
    bad.ticket_times = (100, 1001);
    reject(bad);
    let mut bad = V35FenceInsert::valid(0, 170);
    bad.context_times = (100, 186);
    bad.ticket_times = (100, 185);
    reject(bad);
    let mut bad = V35FenceInsert::valid(0, 180);
    bad.committed_at = 190;
    reject(bad);
}

#[test]
fn v35_migration_is_atomic_and_matcher_rejects_lookalikes() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 34).unwrap();
    let transaction = connection.unchecked_transaction().unwrap();
    transaction.execute_batch(MIGRATION_V35).unwrap();
    install_missing_v12_fence_triggers(&transaction).unwrap();
    transaction.rollback().unwrap();
    assert_eq!(current_schema_marker(&connection), 34);
    assert!(!table_exists(
        &connection,
        "provider_qualification_admission_fences"
    ));

    for mutation in [
        "DROP TRIGGER provider_qualification_fence_no_update",
        "DROP TRIGGER provider_qualification_fence_selector_role",
        "ALTER TABLE provider_qualification_admission_fences ADD COLUMN near_match INTEGER",
        "CREATE TABLE provider_qualification_admission_fence (operation_id BLOB)",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 36).unwrap();
        assert!(project_workspace_schema::v36_matches(&connection, 36).unwrap());
        connection.execute_batch(mutation).unwrap();
        assert!(
            !project_workspace_schema::v36_matches(&connection, 36).unwrap(),
            "{mutation}"
        );
        assert!(
            apply_migrations_internal(&connection, 36).is_err(),
            "{mutation}"
        );
    }
}

fn table_exists(connection: &Connection, name: &str) -> bool {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [name],
            |row| row.get(0),
        )
        .unwrap()
}
