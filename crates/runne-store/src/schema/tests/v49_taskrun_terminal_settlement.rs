#[test]
fn v49_terminal_settlement_receipts_are_append_only_and_reopenable() {
    let path = std::env::temp_dir().join(format!(
        "runne-v49-settlement-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 50).unwrap();
    assert_eq!(schema_marker(&connection), 50);
    assert!(v50_matches(&connection, 50).unwrap());
    let ddl: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_terminal_settlement_receipts'",
        [], |row| row.get(0),
    ).unwrap();
    assert!(ddl.contains("terminal_event_id"));
    drop(connection);
    let reopened = Connection::open(&path).unwrap();
    apply_migrations_internal(&reopened, 50).unwrap();
    assert!(v50_matches(&reopened, 50).unwrap());
    reopened
        .execute("DROP TRIGGER taskrun_terminal_settlement_immutable", [])
        .unwrap();
    assert!(!v50_matches(&reopened, 50).unwrap());
    drop(reopened);
    let _ = std::fs::remove_file(path);
}

#[test]
fn latest_absent_dispatch_rejects_local_row_without_verified_submit_origin() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let mut area = [0_u8; 100];
    area[..4].copy_from_slice(b"RMA1");
    area[4..20].fill(1);
    area[28..36].fill(2);
    area[44..52].fill(3);
    area[52..68].fill(1);
    area[68..84].fill(4);
    area[84..100].fill(5);
    connection
        .execute(
            "INSERT INTO taskrun_local_command_attempts
         (taskrun_id,conversation_id,workspace_id,attempt_id,node_id,node_epoch,fence,
          command_digest,managed_area_identity,state,exit_code,updated_at)
         VALUES (?1,?2,?3,?4,?5,6,7,?6,?7,'completed',0,1)",
            rusqlite::params![
                [1_u8; 16], [2_u8; 16], [3_u8; 16], [4_u8; 16], [5_u8; 16], [8_u8; 32], area
            ],
        )
        .unwrap();
    let success = runne_domain::task_run::TaskRunEvent::TaskRunCompleted {
        result: runne_domain::command::TerminalResult::Success,
    };
    assert!(local_area_identity_matches(&area, &[1; 16], &[4; 16]));
    assert!(
        !local_terminal_proof_matches(&connection, &[1; 16], &[4; 16], &[5; 16], 6, 7, &success,)
            .unwrap(),
        "a local row alone cannot authorize a remote/manual TaskRun terminal"
    );
    assert!(
        !local_terminal_proof_matches(&connection, &[1; 16], &[9; 16], &[5; 16], 6, 7, &success,)
            .unwrap(),
        "a different attempt cannot settle the local terminal"
    );
    let failed = runne_domain::task_run::TaskRunEvent::TaskRunCompleted {
        result: runne_domain::command::TerminalResult::Failure {
            reason: "local_command_exit_0".to_owned(),
        },
    };
    assert!(
        !local_terminal_proof_matches(&connection, &[1; 16], &[4; 16], &[5; 16], 6, 7, &failed,)
            .unwrap(),
        "the event outcome must match the durable exit code"
    );
}

#[test]
fn local_cancellation_requires_a_completed_or_empty_area_state() {
    use runne_domain::task_run::TaskRunEvent;

    for event in [
        TaskRunEvent::TaskRunCancelled,
        TaskRunEvent::CancellationCompleted,
    ] {
        assert!(local_attempt_terminal_state_matches(
            "cancelled",
            None,
            &event
        ));
        assert!(local_attempt_terminal_state_matches(
            "completed",
            Some(17),
            &event
        ));
        assert!(!local_attempt_terminal_state_matches(
            "launch_intent",
            None,
            &event
        ));
        assert!(!local_attempt_terminal_state_matches(
            "cancel_requested",
            None,
            &event
        ));
        assert!(!local_attempt_terminal_state_matches(
            "cancelled",
            Some(0),
            &event
        ));
    }
}

#[test]
fn local_exit_terminal_requires_the_exact_completed_failure_result() {
    use runne_domain::command::TerminalResult;
    use runne_domain::task_run::TaskRunEvent;

    let matching = TaskRunEvent::TaskRunCompleted {
        result: TerminalResult::Failure {
            reason: "local_command_exit_7".to_owned(),
        },
    };
    let wrong_exit = TaskRunEvent::TaskRunCompleted {
        result: TerminalResult::Failure {
            reason: "local_command_exit_8".to_owned(),
        },
    };
    let wrong_variant = TaskRunEvent::TaskRunFailed {
        reason: "local_command_exit_7".to_owned(),
    };
    assert!(local_attempt_terminal_state_matches(
        "completed",
        Some(7),
        &matching
    ));
    assert!(!local_attempt_terminal_state_matches(
        "completed",
        Some(7),
        &wrong_exit
    ));
    assert!(!local_attempt_terminal_state_matches(
        "completed",
        Some(7),
        &wrong_variant
    ));
    assert!(!local_attempt_terminal_state_matches(
        "completed",
        Some(1),
        &TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        }
    ));
}

#[test]
fn local_no_effect_accepts_only_prelaunch_failure_or_cancellation() {
    use runne_domain::task_run::TaskRunEvent;

    for event in [
        TaskRunEvent::TaskRunFailed {
            reason: "dispatch_not_started".to_owned(),
        },
        TaskRunEvent::TaskRunCancelled,
        TaskRunEvent::CancellationCompleted,
    ] {
        assert!(no_effect_terminal_event(
            &TaskRunEventCodec.encode(&event).unwrap()
        ));
    }
    let launched = TaskRunEvent::TaskRunFailed {
        reason: "local_command_exit_1".to_owned(),
    };
    assert!(!no_effect_terminal_event(
        &TaskRunEventCodec.encode(&launched).unwrap()
    ));
}

#[test]
fn prelaunch_local_binding_requires_complete_v51_approval_identity() {
    let unbound = LocalNoEffectRow {
        conversation_id: vec![1; 16],
        workspace_id: vec![2; 16],
        command_digest: vec![3; 32],
        attempt_id: None,
        node_id: None,
        node_epoch: None,
        fence: None,
        area_identity: None,
        state: "no_effect_terminal".into(),
        exit_code: None,
        approval_id: None,
        executable_digest: None,
        workspace_version: None,
        root_version: None,
        root_identity: None,
        trust_epoch: None,
        trust_revision: None,
        source_policy_version: None,
        command_policy_version: None,
    };
    assert!(prelaunch_binding_is_valid(&unbound));

    let mut bound = unbound;
    bound.approval_id = Some(vec![0x41; 16]);
    bound.executable_digest = Some(vec![0x42; 32]);
    bound.workspace_version = Some(1);
    bound.root_version = Some(1);
    bound.root_identity = Some(vec![0x43; 32]);
    bound.trust_epoch = Some(1);
    bound.trust_revision = Some(1);
    bound.source_policy_version = Some(2);
    bound.command_policy_version = Some(1);
    assert!(prelaunch_binding_is_valid(&bound));

    bound.command_policy_version = Some(2);
    assert!(
        !prelaunch_binding_is_valid(&bound),
        "only the current closed local command policy tuple is accepted"
    );
    bound.command_policy_version = Some(1);
    bound.root_identity = None;
    assert!(
        !prelaunch_binding_is_valid(&bound),
        "partial approval provenance cannot certify no effect"
    );
}
