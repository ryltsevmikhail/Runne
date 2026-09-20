// Live-WAL verification of the Windows identity guard at the production
// hot-reader boundary. Reachability notes pinned by the host filesystem:
// the store never enables SQLITE_FCNTL_PERSIST_WAL, so a `-wal` exists only
// while a writer holds it open — and the win32 VFS opens without
// FILE_SHARE_DELETE, so the WAL cannot be renamed or replaced underneath an
// anchored reader. The mismatch arm of the journal identity comparison is
// therefore not constructible through the public store API on this platform;
// the anchor-vs-open comparison is still exercised end to end by the positive
// scenario, and the OS refusal is proven separately.
//
// Probes stay inside the migration-defined `_daemon_info` table: the
// classification matcher pins the exact schema shape and rejects any
// user-created table.

#[cfg(windows)]
#[test]
fn windows_hot_reader_serves_a_live_wal_without_false_rejections() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("event-log.sqlite");
    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    // An allowed write creates the live WAL the reader will anchor.
    writer
        .execute_batch(
            "INSERT INTO _daemon_info (key, value) VALUES ('probe-live-wal', 'one')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        )
        .unwrap();
    let wal = sidecar_path(&path, "-wal");
    assert!(wal.exists());

    // The reader takes the owner-private hot-reader path (sidecars present);
    // its guard must pass the journal/WAL identity comparison branch against
    // the object SQLite actually holds open. Reaching the Classified stage
    // proves the anchor-vs-live-handle comparisons in verify() and
    // verify_with_sidecar_handle() ran and passed.
    let reached_classified = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_flag = std::sync::Arc::clone(&reached_classified);
    let reader = open_connection_for_profile_with_hook(&path, ConnectionMode::Reader, |stage| {
        if matches!(stage, IdentityHookStage::Classified) {
            hook_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    });
    let (reader, _guard) = match reader {
        Ok(reader) => reader,
        Err(error) => panic!(
            "hot reader rejected after classified={}: {error:?}",
            reached_classified.load(std::sync::atomic::Ordering::SeqCst)
        ),
    };
    assert!(reached_classified.load(std::sync::atomic::Ordering::SeqCst));
    let seen: String = reader
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'probe-live-wal'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(seen, "one");

    // Further writes on the writer and a plain re-read stay admitted.
    writer
        .execute_batch(
            "INSERT INTO _daemon_info (key, value) VALUES ('probe-live-wal', 'two')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        )
        .unwrap();
    let seen: String = reader
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'probe-live-wal'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(seen, "two");
    drop(reader);

    // A normal checkpoint is not a substitution and must not be rejected.
    writer
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();

    // A second hot-reader pass after the checkpoint re-anchors the same
    // (truncated in place) WAL object and still admits the connection.
    let reader = open_managed_connection(&path, ConnectionMode::Reader).unwrap();
    let seen: String = reader
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'probe-live-wal'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(seen, "two");
    drop(reader);
    drop(writer);
}

#[cfg(windows)]
#[test]
fn windows_substituting_a_live_wal_is_os_blocked() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("event-log.sqlite");
    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    writer
        .execute_batch("INSERT INTO _daemon_info (key, value) VALUES ('probe-wal', 'one');")
        .unwrap();
    let wal = sidecar_path(&path, "-wal");
    assert!(wal.exists());

    // The win32 VFS holds the WAL without FILE_SHARE_DELETE: no rename (and
    // therefore no delete-and-replace) can substitute the anchored object
    // while the writer lives. This is the platform proof that the live-WAL
    // mismatch scenario cannot be staged; the pre-open substitution window
    // is covered by windows_retained_stage_main_file_swap_is_rejected.
    let displaced = wal.with_extension("displaced");
    assert!(fs::rename(&wal, &displaced).is_err());
    assert!(wal.exists());
    drop(writer);
}
