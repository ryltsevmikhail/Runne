use super::*;
use runne_store::schema::recovery_diagnosis::StoreRecoveryDiagnosis;
use runne_store::schema::{
    apply_migrations, ensure_authority_id, ensure_exact_event_log_lineage_id,
    open_managed_connection,
};

#[test]
fn managed_runtime_reopen_rejects_authority_or_lineage_mismatch() {
    let (_root, path, authority, lineage) = prepared_store();
    drop(
        open_runtime_connection(
            path.to_str().unwrap(),
            ConnectionMode::ValidatedReopen,
            authority,
            lineage,
            "test runtime",
        )
        .unwrap(),
    );
    // An authority/lineage mismatch fails on a healthy-looking file, so its
    // typed recovery state is `Ready`: the file is recovery-healthy and the
    // admission itself was rejected. The typed rejection keeps the identity
    // rejection distinguishable from file health even at `Ready` (DP1
    // section 7) — the diagnosis does not try to see the mismatch itself.
    let mismatches = [
        open_rejected(&path, uuid_v7(3), lineage, "wrong authority"),
        open_rejected(
            &path,
            authority,
            EventLogLineageId::from_bytes(uuid_v7(4)),
            "wrong lineage",
        ),
    ];
    for error in &mismatches {
        let rejection = store_rejection(error);
        assert_eq!(rejection.stage, RuntimeStoreOpenStage::Open);
        assert_eq!(rejection.rejection, RuntimeStoreRejection::IdentityMismatch);
        assert_eq!(rejection.recovery_state, StoreRecoveryDiagnosis::Ready);
        assert_closed_display(error, "IdentityMismatch");
    }
}

#[test]
fn open_failure_surfaces_typed_recovery_state_without_raw_store_error() {
    let (_root, path, authority, lineage) = prepared_store();
    let (root_page, page_size) = existing_table_page(&path, "event_log_state");
    checkpoint_and_remove_sidecars(&path);
    corrupt_table_root_page(&path, root_page, page_size);

    let error = open_rejected(&path, authority, lineage, "corrupt store");
    let rejection = store_rejection(&error);
    // Reopen admission runs no integrity gates, so the corrupt page passes
    // the Open stage and is attributed at the daemon's verify stage
    // (`readiness_from_managed` → `run_startup_gates_raw` →
    // `PRAGMA integrity_check`).
    assert_eq!(rejection.stage, RuntimeStoreOpenStage::Verify);
    // Startup-gate failures raise bare `rusqlite::Error`s without a typed
    // payload in the current store contract, so the honest rejection is
    // `Unavailable` — the typed recovery state carries the file detail
    // (`IntegrityCheckFailed`). Upgrading gate payloads would be a
    // store-contract change, out of scope here.
    assert_eq!(rejection.rejection, RuntimeStoreRejection::Unavailable);
    assert_eq!(
        rejection.recovery_state,
        StoreRecoveryDiagnosis::IntegrityCheckFailed
    );
    assert_closed_display(&error, "IntegrityCheckFailed");
}

fn existing_table_page(path: &std::path::Path, table: &str) -> (usize, usize) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let root_page: usize = connection
        .query_row(
            "SELECT rootpage FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
        .try_into()
        .unwrap();
    let page_size: usize = connection
        .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .unwrap()
        .try_into()
        .unwrap();
    (root_page, page_size)
}

fn corrupt_table_root_page(path: &std::path::Path, root_page: usize, page_size: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    let start = (root_page - 1) * page_size;
    assert!(
        start + 10 <= bytes.len(),
        "corruption target page is absent"
    );
    let header = start + if root_page == 1 { 100 } else { 0 };
    assert_eq!(bytes[header], 0x0d, "fixture root page is not a table leaf");
    // Keep the schema catalog readable but make the canonical table page
    // structurally invalid so the verify-stage integrity check rejects it.
    bytes[header] = 0x00;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn zero_byte_store_pairs_unavailable_rejection_with_typed_recovery_state() {
    let (_root, path, authority, lineage) = prepared_store();
    std::fs::write(&path, b"").unwrap();
    // The reopen path has no zero-byte preflight: SQLite opens the empty
    // file and classification fails with a bare error (no typed payload), so
    // the rejection is `Unavailable`; the diagnosis catches the zero-byte
    // file pre-open (`ZeroByteDatabase`).
    let error = open_rejected(&path, authority, lineage, "zero-byte store");
    let rejection = store_rejection(&error);
    assert_eq!(rejection.stage, RuntimeStoreOpenStage::Open);
    assert_eq!(rejection.rejection, RuntimeStoreRejection::Unavailable);
    assert_eq!(
        rejection.recovery_state,
        StoreRecoveryDiagnosis::ZeroByteDatabase
    );
    assert_closed_display(&error, "ZeroByteDatabase");
}

#[test]
fn owner_private_admission_rejection_carries_typed_diagnostic_at_ready_state() {
    let (_root, path, authority, lineage) = prepared_store();
    checkpoint_and_remove_sidecars(&path);
    // Relax the daemon directory to group-writable: the owner-private
    // admission guard rejects with the typed `FileIdentityUncertain`
    // diagnostic while the file itself stays recovery-healthy — pinning the
    // `Admission` arm of the rejection classification together with the
    // supplementary `Ready` state.
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    let error = open_rejected(&path, authority, lineage, "relaxed permissions");
    let rejection = store_rejection(&error);
    assert_eq!(rejection.stage, RuntimeStoreOpenStage::Open);
    assert_eq!(
        rejection.rejection,
        RuntimeStoreRejection::Admission(SchemaOpenDiagnostic::FileIdentityUncertain)
    );
    assert_eq!(rejection.recovery_state, StoreRecoveryDiagnosis::Ready);
    assert_closed_display(&error, "FileIdentityUncertain");
}

/// Opens a validated reopen of `path` and returns its rejection.
fn open_rejected(
    path: &std::path::Path,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    purpose: &str,
) -> DaemonError {
    open_runtime_connection(
        path.to_str().unwrap(),
        ConnectionMode::ValidatedReopen,
        authority,
        lineage,
        purpose,
    )
    .map(|_| ())
    .unwrap_err()
}

/// Makes the main database self-contained (checkpoint every committed WAL
/// frame, then remove the sidecars) so corruption of the main file cannot
/// be masked by a live `-wal`.
fn checkpoint_and_remove_sidecars(path: &std::path::Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    drop(connection);
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).unwrap();
        }
    }
}

/// Prepares a real file-backed managed store the way daemon startup does
/// and returns its (root, path, authority, lineage).
fn prepared_store() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    [u8; 16],
    EventLogLineageId,
) {
    let root = tempfile::tempdir().unwrap();
    let daemon = root.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon.join("event-log.sqlite");
    let authority = uuid_v7(1);
    let lineage = EventLogLineageId::from_bytes(uuid_v7(2));
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    ensure_authority_id(&connection, &authority).unwrap();
    ensure_exact_event_log_lineage_id(&connection, lineage).unwrap();
    drop(connection);
    (root, path, authority, lineage)
}

fn store_rejection(error: &DaemonError) -> &RuntimeStoreOpenRejection {
    let DaemonError::StoreOpenRejection(rejection) = error else {
        panic!("expected a store open rejection, got {error:?}")
    };
    rejection
}

/// Display must carry the closed typed token and leak neither raw store
/// error text nor the database path (DP1 section 7).
fn assert_closed_display(error: &DaemonError, expected: &str) {
    let message = error.to_string();
    assert!(message.contains(expected), "{message}");
    assert!(!message.contains("file is not a database"), "{message}");
    assert!(!message.contains("event-log.sqlite"), "{message}");
}

fn uuid_v7(last: u8) -> [u8; 16] {
    [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, last,
    ]
}
