use runne_domain::task_run::TaskRunEvent;
use runne_store::codec::{StoreCodec, TaskRunEventCodec};

pub(super) fn assert_single_create(created: &std::path::Path, watch: &std::fs::File) {
    assert!(created.is_file(), "create_new had a real Linux file effect");
    assert_eq!(
        std::fs::read(created).expect("read actual typed create result"),
        super::super::super::CREATE_BYTES
    );
    assert_eq!(
        super::super::super::super::diagnostic::count_watch_mask(watch, libc::IN_CREATE),
        1,
        "typed create produced exactly one Linux IN_CREATE"
    );
}

pub(super) fn assert_create_preserved(created: &std::path::Path) {
    assert!(
        created.is_file(),
        "completed create remains after Store reopen"
    );
    assert_eq!(
        std::fs::read(created).expect("read retained typed create result"),
        super::super::super::CREATE_BYTES
    );
}

pub(super) fn assert_encrypted_audit(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) {
    assert_eq!(
        super::super::super::verify::invocation_count(database, task),
        1
    );
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only typed audit view");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("typed TaskRun UUID")
        .into_bytes();
    let row: (String, usize, usize, usize, usize, bool, i64, bool) = db
        .query_row(
            "SELECT state,length(canonical_arguments),args_plaintext_len,length(helper_receipt_bytes),receipt_plaintext_len,result_bytes IS NULL,local_stop_state,managed_area_identity=empty_proof_identity AND empty_proof_identity IS NOT NULL FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        )
        .expect("read exact typed audit receipt metadata");
    assert_eq!(row.0, "audit_only");
    assert_eq!(row.1, row.2 + 16, "tool arguments remain encrypted");
    assert_eq!(row.3, row.4 + 16, "helper evidence remains encrypted");
    assert!(row.5, "audit evidence cannot feed a tool result");
    assert_eq!(row.6, 2, "managed effect area has an empty stop proof");
    assert!(row.7, "stop proof is bound to the exact managed area");
    assert_eq!(super::super::super::verify::result_count(database, task), 0);
}

pub(super) fn assert_step_outcome_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    expected: usize,
) {
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only pre-continuation TaskRun view");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("typed TaskRun UUID")
        .into_bytes();
    let payloads = db
        .prepare("SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1")
        .expect("prepare TaskRun outcome scan")
        .query_map([task_bytes.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .expect("query TaskRun events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read TaskRun events");
    let actual = payloads
        .iter()
        .filter(|payload| {
            matches!(
                TaskRunEventCodec.decode(payload),
                Ok(TaskRunEvent::StepOutcomeRecorded { .. })
            )
        })
        .count();
    assert_eq!(actual, expected, "typed TaskRun step-outcome count");
}

pub(super) fn provider_round_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> i64 {
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only provider-round view");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("typed TaskRun UUID")
        .into_bytes();
    db.query_row(
        "SELECT count(*) FROM taskrun_provider_round_bindings WHERE taskrun_id=?1",
        [task_bytes.as_slice()],
        |row| row.get(0),
    )
    .expect("read durable provider-round count")
}

pub(super) async fn wait_entered(name: &str) {
    let directory = barrier_dir();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    while !directory.join(format!("{name}.entered")).is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "typed barrier {name} not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

pub(super) fn release(name: &str) {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(barrier_dir().join(format!("{name}.release")))
        .expect("release exact typed barrier once");
}

fn barrier_dir() -> std::path::PathBuf {
    std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("parent supplied typed barrier directory")
}
