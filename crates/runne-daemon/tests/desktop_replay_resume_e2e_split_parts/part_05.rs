fn local_projection_state(database_path: &Path) -> LocalProjectionState {
    Connection::open(database_path)
        .expect("open desktop database")
        .query_row(
            "
            SELECT projections.payload,
                   replay_cursors.applied_cursor,
                   replay_cursors.event_sequence,
                   replay_cursors.generation,
                   projections.projection_revision
            FROM projections
            JOIN replay_cursors USING (
                runtime_authority,
                principal,
                lineage,
                scope
            )
            ",
            [],
            |row| {
                Ok(LocalProjectionState {
                    payload: row.get(0)?,
                    cursor: row.get(1)?,
                    event_sequence: row.get(2)?,
                    generation: row.get(3)?,
                    projection_revision: row.get(4)?,
                })
            },
        )
        .expect("one desktop projection and cursor")
}

fn daemon_has_unacknowledged_delivery(database_path: &Path, generation: u64) -> bool {
    let generation = i64::try_from(generation).expect("generation range");
    open_daemon_database(database_path)
        .query_row(
            "
            SELECT EXISTS (
                SELECT 1
                FROM _replay_subscriptions
                WHERE session_generation = ?1
                  AND last_delivered_position IS NOT NULL
                  AND last_acked_position IS NOT NULL
                  AND last_delivered_position > last_acked_position
            )
            ",
            [generation],
            |row| row.get(0),
        )
        .expect("read interrupted replay session")
}

type ReplaySessionRow = (String, String, Option<i64>, Option<i64>, i64);

fn daemon_replay_rows(database_path: &Path) -> Vec<ReplaySessionRow> {
    let connection = open_daemon_database(database_path);
    let mut statement = connection
        .prepare(
            "SELECT hex(session_id), state, last_acked_position, last_delivered_position, session_generation
             FROM _replay_subscriptions ORDER BY created_at",
        )
        .expect("prepare replay session diagnostics");
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })
        .expect("query replay session diagnostics")
        .collect::<Result<Vec<_>, _>>()
        .expect("read replay session diagnostics")
}

fn daemon_latest_cursor_is_acknowledged_and_closed(database_path: &Path, generation: u64) -> bool {
    let generation = i64::try_from(generation).expect("generation range");
    open_daemon_database(database_path)
        .query_row(
            "
            SELECT EXISTS (
                SELECT 1
                FROM _replay_subscriptions
                WHERE session_generation = ?1
                  AND last_delivered_position IS NOT NULL
                  AND last_acked_position IS NOT NULL
                  AND last_delivered_position = last_acked_position
                  AND state = 'closed'
            )
            ",
            [generation],
            |row| row.get(0),
        )
        .expect("read resumed replay session")
}

fn open_daemon_database(database_path: &Path) -> Connection {
    let connection = Connection::open(database_path).expect("open daemon database");
    runne_sqlite_handle_identity::configure_persistent_wal(&connection)
        .expect("retain daemon WAL for cross-process fault inspection");
    connection
}

fn wait_for_daemon_latest_cursor_acknowledged_and_closed(database_path: &Path, generation: u64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if daemon_latest_cursor_is_acknowledged_and_closed(database_path, generation) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "snapshot reconciliation must acknowledge then close its replay session"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(path)
            .expect("temporary directory metadata")
            .permissions()
            .mode()
            & 0o077,
        0
    );
}

fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set owner-only directory permissions");
    assert_owner_only(path);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_live_epoch_revocation_closes_revoked_without_local_mutation() {
    let _process_guard = process_e2e_guard().await;
    let fixture = ProcessFaultFixture::open().await;
    let before = local_projection_state(&fixture.desktop_database);
    let mut live = fixture.open_raw_live(&before.cursor).await;
    revoke_live_replay_epoch(&fixture.daemon_database);

    let error = live
        .next_event()
        .await
        .expect_err("authorization epoch mismatch must fail closed");

    assert_eq!(
        error.recovery_disposition(),
        ReplayRecoveryDisposition::Revoked
    );
    assert_eq!(local_projection_state(&fixture.desktop_database), before);
}
