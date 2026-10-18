use super::fixture::{
    RecoveryFixture, attempt_row, reopen_recovery_candidate, scalar, taskrun_event_count,
};
use runne_application::ports::{EventStore, ExecutionNodeId};
use runne_store::store::LocalCommandCancellationStopEvidence;

/// Inserts a durable permission stop row with the given reason, anchored at
/// the last durable stream event (the `CancellationRequested` of the crash
/// window), exactly like the live first-writer stop commits.
fn insert_stop_row(fixture: &RecoveryFixture, reason: i64) {
    let (event_id, sequence): (Vec<u8>, i64) = fixture
        .database
        .connection()
        .query_row(
            "SELECT event_id,sequence FROM events WHERE aggregate_type=1 AND aggregate_id=?1
             ORDER BY sequence DESC LIMIT 1",
            [fixture.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    fixture
        .database
        .connection()
        .execute(
            "INSERT INTO x2_permission_stop(taskrun_id,attempt_id,binding_digest,stop_id,reason,
             observed_version,event_id,stopped_at)
             SELECT ?1,attempt_id,binding_digest,?2,?3,?4,?5,1
             FROM x2_permission_bindings WHERE taskrun_id=?1",
            rusqlite::params![
                fixture.taskrun_id.as_bytes(),
                [0x31_u8; 16].as_slice(),
                reason,
                sequence,
                event_id.as_slice()
            ],
        )
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn compatible_stop_reasons_complete_while_reason_six_blocks() {
    // Reasons 2..=5 are cancellation-compatible stop observations exactly as
    // the live terminal validation accepts them; recovery must complete the
    // durable cancellation WITHOUT touching the retained reason. Reason 6 is
    // the only conflicting class: it never authorizes a completion.
    for (reason, completes) in [(2, true), (3, true), (4, true), (5, true), (6, false)] {
        let fixture = super::fixture::prepare_recovery_fixture(
            &format!("cancel-stop-reason-{reason}"),
            0x80 + reason as u8,
            true,
            "cancel_requested",
            None,
        )
        .await;
        insert_stop_row(&fixture, reason);
        let (store, node_id, epoch, candidate) = reopen_recovery_candidate(&fixture);
        let evidence = store
            .local_command_cancellation_stop_evidence(
                fixture.taskrun_id,
                candidate.identity.attempt_id,
            )
            .unwrap();
        if completes {
            assert_eq!(evidence, LocalCommandCancellationStopEvidence::Proven);
            store
                .complete_local_command_cancellation_recovery(
                    &candidate,
                    &ExecutionNodeId(node_id),
                    epoch,
                    fixture.area.prove_empty().unwrap(),
                )
                .unwrap();
            assert_eq!(
                scalar(
                    &fixture,
                    "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1"
                ),
                1,
                "reason {reason} completes the cancellation (live-path parity)"
            );
            assert_eq!(
                scalar(
                    &fixture,
                    "SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND state='released'"
                ),
                1
            );
            let run = store.load_task_run(fixture.taskrun_id).unwrap();
            assert!(run.events.last().is_some_and(|event| {
                matches!(
                    event.payload(),
                    runne_domain::task_run::TaskRunEvent::CancellationCompleted
                )
            }));
        } else {
            assert_eq!(
                evidence,
                LocalCommandCancellationStopEvidence::ConflictingStop,
                "reason {reason} owns the attempt without a cancellation proof"
            );
            let events_before = taskrun_event_count(&fixture);
            assert!(
                store
                    .complete_local_command_cancellation_recovery(
                        &candidate,
                        &ExecutionNodeId(node_id),
                        epoch,
                        fixture.area.prove_empty().unwrap(),
                    )
                    .is_err(),
                "reason {reason} must not complete the cancellation"
            );
            assert_eq!(taskrun_event_count(&fixture), events_before);
            assert_eq!(
                scalar(
                    &fixture,
                    "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1"
                ),
                0
            );
            assert_eq!(attempt_row(&fixture).0, "cancel_requested");
        }
        let retained_reason: i64 = fixture
            .database
            .connection()
            .query_row(
                "SELECT reason FROM x2_permission_stop WHERE taskrun_id=?1",
                [fixture.taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            retained_reason, reason,
            "the first-writer stop reason is never overwritten"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tampered_binding_is_rejected_without_artifacts() {
    let plain = |fixture: &RecoveryFixture| {
        rusqlite::Connection::open(fixture.database.file.path()).unwrap()
    };
    for (name, sql) in [
        (
            "digest",
            "UPDATE x2_permission_bindings SET binding_digest=?2 WHERE taskrun_id=?1",
        ),
        (
            "blob",
            "UPDATE x2_permission_bindings SET binding=X'7b' WHERE taskrun_id=?1",
        ),
        (
            "owner",
            "UPDATE x2_permission_bindings SET native_owner_id=?2 WHERE taskrun_id=?1",
        ),
    ] {
        let fixture = super::fixture::prepare_recovery_fixture(
            &format!("cancel-stop-tamper-{name}"),
            0x90,
            true,
            "cancel_requested",
            None,
        )
        .await;
        let (store, node_id, epoch, candidate) = reopen_recovery_candidate(&fixture);
        // The immutable-row guard normally makes this tamper impossible; the
        // test bypasses it only to prove the reader still fails closed.
        let connection = plain(&fixture);
        connection
            .execute("DROP TRIGGER x2_permission_bindings_immutable", [])
            .unwrap();
        let tampered_32 = [0x77_u8; 32];
        let tampered_16 = [0x77_u8; 16];
        if name == "digest" {
            connection
                .execute(
                    sql,
                    rusqlite::params![fixture.taskrun_id.as_bytes(), tampered_32.as_slice()],
                )
                .unwrap();
        } else if name == "owner" {
            connection
                .execute(
                    sql,
                    rusqlite::params![fixture.taskrun_id.as_bytes(), tampered_16.as_slice()],
                )
                .unwrap();
        } else {
            connection
                .execute(sql, [fixture.taskrun_id.as_bytes()])
                .unwrap();
        }
        assert!(
            store
                .local_command_cancellation_stop_evidence(
                    fixture.taskrun_id,
                    candidate.identity.attempt_id
                )
                .is_err(),
            "a tampered {name} column is corruption, not missing evidence"
        );
        let events_before: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1",
                [fixture.taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            store
                .complete_local_command_cancellation_recovery(
                    &candidate,
                    &ExecutionNodeId(node_id),
                    epoch,
                    fixture.area.prove_empty().unwrap(),
                )
                .is_err()
        );
        let count = |sql: &str| -> i64 {
            connection
                .query_row(sql, [fixture.taskrun_id.as_bytes()], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(
            count("SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1"),
            events_before
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1"),
            0
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1"),
            0,
            "no stop reason is recorded from a tampered binding"
        );
        drop(connection);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn binding_fence_is_protected_by_the_foreign_key() {
    let fixture = super::fixture::prepare_recovery_fixture(
        "cancel-stop-fence-fk",
        0x95,
        true,
        "cancel_requested",
        None,
    )
    .await;
    assert!(
        fixture
            .database
            .connection()
            .execute(
                "UPDATE x2_permission_bindings SET fence=fence+1 WHERE taskrun_id=?1",
                [fixture.taskrun_id.as_bytes()],
            )
            .is_err(),
        "the assignment foreign key makes an off-fence binding unreachable"
    );
}
