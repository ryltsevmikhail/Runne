use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::Command;

use rusqlite::{TransactionBehavior, params};

const MODE: &str = "RUNNE_QUALIFICATION_RUNNER_CRASH_MODE";
const ROOT: &str = "RUNNE_QUALIFICATION_RUNNER_CRASH_ROOT";
const CHILD: &str = "ledger::tests::crash::crash_child_process";

#[test]
fn crash_before_commit_recovers_without_consuming() {
    let root = super::private_root();
    crash("before", root.path());
    super::open(&root)
        .consume_fault(super::fixture::facts([1, 2, 3, 4]), super::binding(5, 6))
        .expect("hot journal rolls back before a durable commit");
}

#[test]
fn crash_after_commit_keeps_replay_consumed() {
    let root = super::private_root();
    crash("after", root.path());
    assert!(
        super::open(&root)
            .consume_fault(super::fixture::facts([1, 2, 3, 4]), super::binding(5, 6))
            .is_err()
    );
}

#[test]
fn crash_after_run_commit_keeps_bootstrap_consumed() {
    let root = super::private_root();
    crash("after-run", root.path());
    assert!(
        super::open(&root)
            .consume_run(super::run_fixture::proof([1, 2], 5, 6))
            .is_err()
    );
    assert!(
        super::open(&root)
            .consume_run(super::run_fixture::proof([7, 8], 5, 6))
            .is_err()
    );
}

#[test]
fn crash_child_process() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var(ROOT).expect("child root"));
    let mut ledger =
        super::QualificationReplayLedger::open_for_test(&root, super::uid()).expect("child ledger");
    let facts = super::fixture::facts([1, 2, 3, 4]);
    let binding = super::binding(5, 6);
    let record = crate::record::FaultRecord::from_facts(&facts, &binding).expect("record");
    match mode.as_str() {
        "after-run" => {
            let proof = super::run_fixture::proof([1, 2], 5, 6);
            let record = crate::run_record::RunRecord::from_facts(&proof).unwrap();
            ledger
                .consume_run_record(&record)
                .expect("committed run before ACK");
            std::process::abort();
        }
        "after" => {
            ledger.consume_record(&record).expect("committed record");
            let count: i64 = ledger
                .connection
                .query_row("SELECT COUNT(*) FROM fault_cases", [], |row| row.get(0))
                .expect("committed row");
            assert_eq!(count, 1, "commit precedes acknowledgement");
            std::process::abort();
        }
        "before" => {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("child transaction");
            transaction
                .execute(
                    "INSERT INTO immutable_runs (source_revision, workflow_run_id, namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![record.source.as_slice(), record.run, record.namespace.as_slice(), record.candidate.as_slice(), record.raw_tuple.as_slice(), record.manifest.as_slice(), record.profile.as_slice()],
                )
                .expect("uncommitted write");
            transaction.cache_flush().expect("spill dirty pages");
            let journal = root.join("ledger.sqlite3-journal");
            assert!(journal.is_file(), "dirty journal");
            assert!(
                std::fs::metadata(journal).expect("journal metadata").len() > 0,
                "journal has recovery data"
            );
            std::process::abort();
        }
        _ => panic!("unknown crash mode"),
    }
}

fn crash(mode: &str, root: &Path) {
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg(CHILD)
        .env(MODE, mode)
        .env(ROOT, root)
        .status()
        .expect("child process");
    assert_eq!(status.signal(), Some(6), "child must abort after the write");
}
