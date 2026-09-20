// Windows regression: the released v39 → v40 migration under a live WAL,
// followed by guarded managed access (hot reader + validated reopen).
//
// Lifecycle fidelity — the documented store lifecycle is respected end to
// end, no lock or sidecar is bypassed:
// 1. the v39 schema is staged on a plain connection in WAL mode; the staged
//    conversation row and the upgrade run through the public
//    `apply_migrations` (the migration's own Exclusive transaction, whose
//    trailing `wal_checkpoint(FULL)` folds the frames into the main
//    database) on that same connection;
// 2. the WAL sidecar itself stays present until the staging connection
//    closes; the documented end of life is that clean close, which removes
//    the sidecars and admits managed access;
// 3. managed access is then admitted: writer (explicit post-v40 scope
//    marker), owner-private hot reader through the FILE_ID_INFO identity
//    guard, and a validated reopen.
//
// Contract under test: pre-v40 conversations keep their durable rows but
// gain NO context-scope marker — unknown provenance stays denied, and
// nothing is backfilled into `text_only`.

#[cfg(windows)]
#[test]
fn windows_v39_to_v40_migration_preserves_live_wal_conversations_without_scope_backfill() {
    // Nested fixture: the guard validates and restricts the parent and
    // grandparent of the database, both inside the test-owned tempdir.
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    let path = daemon.join("event-log.sqlite");

    // Stage the released v39 schema on a raw connection in WAL mode.
    let staging = Connection::open(&path).unwrap();
    staging
        .pragma_update(None, "journal_mode", "wal")
        .expect("wal journal mode");
    apply_migrations_internal(&staging, 39).expect("v39 schema");
    assert_eq!(schema_marker(&staging), 39);

    // A pre-v40 conversation: a durable aggregate stream and — by the v39
    // shape — no context-scope row at all (the table does not exist yet).
    let old_conversation = [7_u8; 16];
    staging
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, created_at)
             VALUES (2, ?1, 0, 1)",
            [old_conversation.as_slice()],
        )
        .unwrap();
    assert!(
        staging
            .execute(
                "INSERT INTO conversation_context_scope
                 (conversation_id, context_scope, recorded_at) VALUES (?1, 'workspace', 1)",
                [old_conversation.as_slice()],
            )
            .is_err(),
        "v39 schema must not carry the context-scope table"
    );

    // The upgrade runs on the WAL-owning connection through the public API;
    // the WAL sidecar is still present afterwards (the API's own trailing
    // checkpoint keeps the sidecar in place until close).
    apply_migrations(&staging).unwrap();
    assert_eq!(schema_marker(&staging), 40);
    assert!(sidecar_path(&path, "-wal").exists());
    let preserved: i64 = staging
        .query_row(
            "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preserved, 1, "the pre-v40 conversation was lost");
    let scope_rows: i64 = staging
        .query_row("SELECT COUNT(*) FROM conversation_context_scope", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(scope_rows, 0, "migration must not backfill scope markers");

    // Documented WAL end of life: clean close checkpoints and removes the
    // sidecars, which is what admits a fresh managed writer. While the
    // sidecars are live, a second writer is refused (SidecarPresent) —
    // pinned here so the refusal stays part of the tested contract.
    drop(staging);
    assert!(!sidecar_path(&path, "-wal").exists() || {
        let refused = open_managed_connection(&path, ConnectionMode::Writer);
        refused.is_err()
    });

    // Managed writer over the migrated database; a new conversation is
    // created with its explicit post-v40 workspace marker next to the
    // unclassified old one.
    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    let new_conversation = [9_u8; 16];
    writer
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, created_at)
             VALUES (2, ?1, 1, 2)",
            [new_conversation.as_slice()],
        )
        .unwrap();
    writer
        .execute(
            "INSERT INTO conversation_context_scope
             (conversation_id, context_scope, recorded_at) VALUES (?1, 'workspace', 2)",
            [new_conversation.as_slice()],
        )
        .unwrap();

    // With the writer live the sidecars are present, so the reader takes the
    // owner-private hot-reader path: the identity guard compares SQLite's
    // live main handle and live WAL handle against the retained anchors.
    let reader = open_managed_connection(&path, ConnectionMode::Reader).unwrap();
    let conversations: i64 = reader
        .query_row(
            "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(conversations, 2);
    let old_scope: Option<String> = reader
        .query_row(
            "SELECT context_scope FROM conversation_context_scope
             WHERE conversation_id = ?1",
            [old_conversation.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(old_scope, None, "old conversations stay unclassified");
    let new_scope: String = reader
        .query_row(
            "SELECT context_scope FROM conversation_context_scope
             WHERE conversation_id = ?1",
            [new_conversation.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(new_scope, "workspace");
    drop(reader);

    // A validated reopen re-runs the identity guard (main + sidecar anchors)
    // against the live-WAL database and stays admitted.
    let reopened =
        reopen_managed_connection_validated(&path, ConnectionMode::ValidatedReopen, |_| Ok(()));
    assert!(reopened.is_ok());
}
