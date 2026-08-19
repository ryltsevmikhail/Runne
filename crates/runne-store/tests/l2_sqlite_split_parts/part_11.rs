// ── Test 1: PRAGMA profile ───────────────────────────────────────────────

#[test]
fn test_pragma_profile() {
    let database = validated_reopen::ValidatedTestDatabase::new("pragma");
    let db_path = database.path().to_owned();
    cleanup_db(&db_path);

    let (_store, identity) = validated_reopen::initialize_store(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();

    // Verify PRAGMAs via direct rusqlite connection
    let conn = validated_reopen_store::open_validated_reader(&db_path, identity).unwrap();

    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, "wal", "expected WAL journal mode");

    let synchronous: i32 = conn
        .query_row("PRAGMA synchronous;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(synchronous, 2, "expected FULL synchronous (2)");

    let fk: i32 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(fk, 1, "expected foreign_keys = ON");

    #[cfg(target_os = "macos")]
    {
        let fullfsync: i32 = conn
            .query_row("PRAGMA fullfsync;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fullfsync, 1, "expected fullfsync = 1 on macOS");
    }

    cleanup_db(&db_path);
}
