use super::{binding, fixture, open, private_root, run_fixture::proof};

#[test]
fn run_is_consumed_across_reopen_and_cannot_restart_with_new_ids() {
    let root = private_root();
    open(&root).consume_run(proof([1, 2], 5, 6)).unwrap();
    assert!(open(&root).consume_run(proof([1, 2], 5, 6)).is_err());
    assert!(open(&root).consume_run(proof([7, 8], 5, 6)).is_err());
    open(&root)
        .consume_fault(fixture::facts([7, 8, 9, 10]), binding(5, 6))
        .unwrap();
}

#[test]
fn run_and_fault_share_independent_context_replay_domains() {
    for ids in [[1, 8], [7, 2]] {
        let root = private_root();
        open(&root)
            .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            .unwrap();
        assert!(open(&root).consume_run(proof(ids, 5, 6)).is_err());
        open(&root).consume_run(proof([7, 8], 5, 6)).unwrap();
    }
    let root = private_root();
    open(&root).consume_run(proof([1, 2], 5, 6)).unwrap();
    for ids in [[1, 8, 9, 10], [7, 2, 9, 10]] {
        assert!(
            open(&root)
                .consume_fault(fixture::facts(ids), binding(5, 6))
                .is_err()
        );
    }
    open(&root)
        .consume_fault(fixture::facts([7, 8, 9, 10]), binding(5, 6))
        .unwrap();
}

#[test]
fn immutable_manifest_and_profile_apply_to_both_record_types() {
    for (manifest, profile) in [(15, 6), (5, 16)] {
        let root = private_root();
        open(&root)
            .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            .unwrap();
        assert!(
            open(&root)
                .consume_run(proof([7, 8], manifest, profile))
                .is_err()
        );
        open(&root).consume_run(proof([7, 8], 5, 6)).unwrap();
        assert!(
            open(&root)
                .consume_fault(fixture::facts([9, 10, 11, 12]), binding(manifest, profile))
                .is_err()
        );
    }
}

#[test]
fn run_key_deletion_or_wrong_association_refuses_reopen() {
    for mutation in [
        "DELETE FROM replay_keys WHERE domain=1",
        "INSERT INTO immutable_runs SELECT source_revision, 'orphan', namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256 FROM immutable_runs;",
        "DELETE FROM run_bootstraps",
        "INSERT INTO fault_cases SELECT context_id, context_nonce, context_id, context_nonce, randomblob(32), source_revision, workflow_run_id, namespace_sha256 FROM run_bootstraps; INSERT INTO replay_keys SELECT 3, context_id, source_revision, workflow_run_id, namespace_sha256 FROM run_bootstraps; INSERT INTO replay_keys SELECT 4, context_nonce, source_revision, workflow_run_id, namespace_sha256 FROM run_bootstraps;",
        "INSERT INTO immutable_runs SELECT source_revision, 'other-run', namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256 FROM immutable_runs; UPDATE replay_keys SET workflow_run_id='other-run' WHERE domain=2;",
    ] {
        let root = private_root();
        open(&root).consume_run(proof([1, 2], 5, 6)).unwrap();
        rusqlite::Connection::open(root.path().join(crate::path_guard::DATABASE_NAME))
            .unwrap()
            .execute_batch(mutation)
            .unwrap();
        assert!(
            crate::QualificationReplayLedger::open_for_test(root.path(), super::uid()).is_err()
        );
    }
}

#[test]
#[allow(clippy::needless_collect)] // Spawn all barrier participants before joining.
fn concurrent_run_consumers_have_one_winner() {
    let root = std::sync::Arc::new(private_root());
    drop(open(&root));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let joins: Vec<_> = (0_u8..4)
        .map(|offset| {
            let root = std::sync::Arc::clone(&root);
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                crate::QualificationReplayLedger::open_for_test(root.path(), super::uid())
                    .and_then(|mut ledger| {
                        ledger.consume_run(proof([1 + offset, 10 + offset], 5, 6))
                    })
                    .is_ok()
            })
        })
        .collect();
    let successes = joins
        .into_iter()
        .map(|join| usize::from(join.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
}

#[test]
fn stale_verified_proof_cannot_be_first_consumed() {
    for boundary in [0, 1, 2] {
        let root = private_root();
        let proof = proof([1, 2], 5, 6);
        let now = match boundary {
            0 => proof.issued_at() - 1,
            1 => proof.expires_at(),
            _ => proof.run_not_after(),
        };
        let mut ledger = open(&root);
        assert!(ledger.consume_run_at(proof, now).is_err());
        let count: i64 = ledger
            .connection
            .query_row("SELECT COUNT(*) FROM replay_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(ledger);
        open(&root)
            .consume_run(super::run_fixture::proof([1, 2], 5, 6))
            .unwrap();
    }
}

#[test]
fn waiting_for_writer_lock_does_not_extend_admission() {
    let root = private_root();
    let mut ledger = open(&root);
    let path = root.path().join(crate::path_guard::DATABASE_NAME);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let connection = rusqlite::Connection::open(path).unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        ready_tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        connection.execute_batch("ROLLBACK").unwrap();
    });
    ready_rx.recv().unwrap();
    let proof = super::run_fixture::proof_with_window([1, 2], 5, 6, 2);
    assert!(ledger.consume_run(proof).is_err());
    blocker.join().unwrap();
    drop(ledger);
    let mut ledger = open(&root);
    let count: i64 = ledger
        .connection
        .query_row("SELECT COUNT(*) FROM replay_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    ledger
        .consume_run(super::run_fixture::proof([1, 2], 5, 6))
        .unwrap();
}
