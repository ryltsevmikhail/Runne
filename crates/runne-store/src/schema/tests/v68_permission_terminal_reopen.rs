const V68_TASK: [u8; 16] = [0x71; 16];
const V68_ATTEMPT: [u8; 16] = [0x72; 16];
const V68_NODE: [u8; 16] = [0x73; 16];
const V68_EVENT: [u8; 16] = [0x74; 16];
const V68_FENCE: i64 = 9;
const V68_EPOCH: i64 = 5;
const V68_VERSION: i64 = 12;
const V68_LEASE: i64 = 4_102_444_800_000;

/// Builds the settled row chain of a live V68 CurrentPermission cancellation:
/// receipt, terminal event, sidecar, spent binding, released occupation.
#[expect(
    clippy::too_many_arguments,
    reason = "the fixture pins every tamperable linkage dimension of the settled receipt"
)]
fn v68_reopen_fixture(
    attempt_state: &str,
    attempt_exit: Option<i64>,
    exit_kind: i64,
    sidecar_exit: Option<i64>,
    signal: Option<i64>,
    sidecar_event: [u8; 16],
    sidecar_version: i64,
    relax_terminal_guard: bool,
) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    insert_v68_preflight(&connection, V68_TASK, "preflight");
    connection
        .execute(
            "INSERT INTO taskrun_local_permission_routes
             (taskrun_id,route,provenance,cutover_version) VALUES (?1,2,3,68)",
            [V68_TASK.as_slice()],
        )
        .unwrap();
    let mut area = [0_u8; 100];
    area[..4].copy_from_slice(b"RMA1");
    area[4..20].fill(1);
    area[28..36].fill(2);
    area[44..52].fill(3);
    area[52..68].copy_from_slice(&V68_TASK);
    area[68..84].copy_from_slice(&V68_ATTEMPT);
    area[84..100].fill(5);
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type,aggregate_id,current_version,last_event_id,last_timestamp,created_at)
             VALUES(1,?1,?2,?3,1,1)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_VERSION,
                V68_EVENT.as_slice()
            ],
        )
        .unwrap();
    let payload = TaskRunEventCodec
        .encode(&TaskRunEvent::CancellationCompleted)
        .unwrap();
    let foreign_event = [0x79_u8; 16];
    for (event_id, sequence) in [(V68_EVENT, V68_VERSION), (foreign_event, V68_VERSION + 1)] {
        connection
            .execute(
                "INSERT INTO events(event_id,aggregate_type,aggregate_id,sequence,global_position,
                 timestamp,sensitivity,schema_version,causation_id,command_id,idempotency_key,actor,
                 payload,integrity_digest,correlation_id,correlation_type,integrity_profile)
                 VALUES(?1,1,?2,?3,?3,1,0,1,NULL,?4,?5,?6,?7,?8,?9,1,1)",
                rusqlite::params![
                    event_id.as_slice(),
                    V68_TASK.as_slice(),
                    sequence,
                    [0x75_u8; 16].as_slice(),
                    "v68-reopen-idem",
                    "v68-reopen-actor",
                    payload,
                    [0xAB_u8; 32].as_slice(),
                    [0x76_u8; 16].as_slice()
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,?4,?5,'linux-executor-v1',?6,?7,?8,?9)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_ATTEMPT.as_slice(),
                V68_NODE.as_slice(),
                V68_EPOCH,
                V68_FENCE,
                V68_LEASE,
                [0x75_u8; 16].as_slice(),
                [0x77_u8; 16].as_slice(),
                [0x78_u8; 16].as_slice()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE taskrun_local_command_attempts SET attempt_id=?1,node_id=?2,node_epoch=?3,
             fence=?4,managed_area_identity=?5,updated_at=1 WHERE taskrun_id=?6",
            rusqlite::params![
                V68_ATTEMPT.as_slice(),
                V68_NODE.as_slice(),
                V68_EPOCH,
                V68_FENCE,
                area.as_slice(),
                V68_TASK.as_slice()
            ],
        )
        .unwrap();
    let mut chain: Vec<&str> = vec!["approved", "launch_intent", "release_reserved", "running"];
    match attempt_state {
        "completed" => chain.push("completed"),
        "cancelled" => {
            chain.push("cancel_requested");
            chain.push("cancelled");
        }
        "running" => {}
        other => panic!("unsupported fixture state {other}"),
    }
    let last = chain.len() - 1;
    for (index, state) in chain.iter().enumerate() {
        if index == last {
            connection
                .execute(
                    "UPDATE taskrun_local_command_attempts SET state=?1,exit_code=?2,updated_at=1
                     WHERE taskrun_id=?3",
                    rusqlite::params![state, attempt_exit, V68_TASK.as_slice()],
                )
                .unwrap();
        } else {
            connection
                .execute(
                    "UPDATE taskrun_local_command_attempts SET state=?1,updated_at=1
                     WHERE taskrun_id=?2",
                    rusqlite::params![state, V68_TASK.as_slice()],
                )
                .unwrap();
        }
    }
    connection
        .execute(
            "INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_FENCE,
                V68_ATTEMPT.as_slice(),
                V68_NODE.as_slice(),
                V68_EPOCH,
                V68_EVENT.as_slice(),
                V68_VERSION
            ],
        )
        .unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER x2_permission_bindings_route_guard;
             DROP TRIGGER x2_permission_human_approval_guard;",
        )
        .unwrap();
    if relax_terminal_guard {
        connection
            .execute("DROP TRIGGER x2_permission_terminal_receipt_guard", [])
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO x2_permission_bindings(taskrun_id,attempt_id,fence,invocation_id,binding_digest,codec_version,binding,native_owner_id,native_owner_generation,selection_managed_policy_version,selection_managed_policy_digest,captured_at) VALUES(?1,?2,?3,?4,?5,1,X'88',?6,?7,0,?8,1)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_ATTEMPT.as_slice(),
                V68_FENCE,
                [0x81_u8; 16].as_slice(),
                [0x8B_u8; 32].as_slice(),
                [0x8D_u8; 16].as_slice(),
                [0x8E_u8; 8].as_slice(),
                [0x8F_u8; 32].as_slice()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO x2_permission_admission(taskrun_id,attempt_id,binding_digest,admission_kind,proof_digest,admitted_at) VALUES(?1,?2,?3,1,NULL,1)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_ATTEMPT.as_slice(),
                [0x8B_u8; 32].as_slice()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO x2_permission_spent(taskrun_id,attempt_id,binding_digest,invocation_id,area_identity,owner_id,owner_generation,burn_id,burned_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_ATTEMPT.as_slice(),
                [0x8B_u8; 32].as_slice(),
                [0x81_u8; 16].as_slice(),
                area.as_slice(),
                [0x8D_u8; 16].as_slice(),
                [0x8E_u8; 8].as_slice(),
                [0x94_u8; 16].as_slice()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO x2_permission_terminal(taskrun_id,attempt_id,binding_digest,terminal_kind,exit_kind,exit_code,signal,stdout,stderr,stdout_observed,stderr_observed,stdout_eof,stderr_eof,stdout_truncated,stderr_truncated,area_empty,event_id,fence,terminal_version,settled_at) VALUES(?1,?2,?3,1,?4,?5,?6,X'',X'',0,0,1,1,0,0,1,?7,?8,?9,1)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_ATTEMPT.as_slice(),
                [0x8B_u8; 32].as_slice(),
                exit_kind,
                sidecar_exit,
                signal,
                sidecar_event.as_slice(),
                V68_FENCE,
                sidecar_version
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent,release_event_id) VALUES(?1,?2,?3,?4,?5,?6,'released','absent',?7)",
            rusqlite::params![
                V68_TASK.as_slice(),
                V68_FENCE,
                V68_ATTEMPT.as_slice(),
                V68_NODE.as_slice(),
                V68_EPOCH,
                V68_LEASE,
                sidecar_event.as_slice()
            ],
        )
        .unwrap();
    connection
}

fn v68_matches_fixture(connection: &Connection, event: &TaskRunEvent) -> bool {
    v68_current_route_terminal_matches(
        connection,
        V68_TASK.as_slice(),
        V68_ATTEMPT.as_slice(),
        V68_NODE.as_slice(),
        V68_EPOCH,
        V68_FENCE,
        V68_EVENT.as_slice(),
        V68_VERSION,
        event,
    )
    .unwrap()
}

#[test]
fn v68_live_cancelled_signalled_stop_with_matching_sidecar_is_admitted() {
    let connection = v68_reopen_fixture("cancelled", Some(137), 2, None, Some(9), V68_EVENT, V68_VERSION, false);
    assert!(v68_matches_fixture(&connection, &TaskRunEvent::CancellationCompleted));
    assert!(v68_matches_fixture(&connection, &TaskRunEvent::TaskRunCancelled));
}

#[test]
fn v68_live_exited_stop_after_cancel_matches_its_factual_exit() {
    let connection = v68_reopen_fixture("completed", Some(7), 1, Some(7), None, V68_EVENT, V68_VERSION, false);
    assert!(v68_matches_fixture(&connection, &TaskRunEvent::CancellationCompleted));
}

#[test]
fn v68_tampered_attempt_rows_are_rejected() {
    let tampered_exit = v68_reopen_fixture("cancelled", Some(0), 2, None, Some(9), V68_EVENT, V68_VERSION, false);
    assert!(!v68_matches_fixture(&tampered_exit, &TaskRunEvent::CancellationCompleted));
    let wrong_state = v68_reopen_fixture("running", Some(137), 2, None, Some(9), V68_EVENT, V68_VERSION, false);
    assert!(!v68_matches_fixture(&wrong_state, &TaskRunEvent::CancellationCompleted));
    let mismatched_kind = v68_reopen_fixture("cancelled", Some(7), 1, Some(9), None, V68_EVENT, V68_VERSION, false);
    assert!(!v68_matches_fixture(&mismatched_kind, &TaskRunEvent::CancellationCompleted));
}

#[test]
fn v68_recovery_null_exit_completion_is_not_admitted_by_the_sidecar_matcher() {
    let recovery = v68_reopen_fixture("cancelled", None, 2, None, Some(9), V68_EVENT, V68_VERSION, false);
    assert!(!v68_matches_fixture(&recovery, &TaskRunEvent::CancellationCompleted));
    assert!(local_attempt_terminal_state_matches("cancelled", None, &TaskRunEvent::CancellationCompleted));
}

#[test]
fn v68_sidecar_linking_a_foreign_event_version_or_type_is_rejected() {
    let foreign = v68_reopen_fixture("cancelled", Some(137), 2, None, Some(9), [0x79; 16], V68_VERSION, true);
    assert!(!v68_matches_fixture(&foreign, &TaskRunEvent::CancellationCompleted));
    let wrong_version = v68_reopen_fixture("cancelled", Some(137), 2, None, Some(9), V68_EVENT, 13, true);
    assert!(!v68_matches_fixture(&wrong_version, &TaskRunEvent::CancellationCompleted));
    let wrong_type = v68_reopen_fixture("cancelled", Some(137), 2, None, Some(9), V68_EVENT, V68_VERSION, false);
    assert!(!v68_matches_fixture(
        &wrong_type,
        &TaskRunEvent::TaskRunCompleted {
            result: runne_domain::command::TerminalResult::Success
        }
    ));
}
