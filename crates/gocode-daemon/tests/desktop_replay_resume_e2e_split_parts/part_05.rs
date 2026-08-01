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
    Connection::open(database_path)
        .expect("open daemon database")
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

fn daemon_latest_cursor_is_acknowledged(database_path: &Path, generation: u64) -> bool {
    let generation = i64::try_from(generation).expect("generation range");
    Connection::open(database_path)
        .expect("open daemon database")
        .query_row(
            "
            SELECT EXISTS (
                SELECT 1
                FROM _replay_subscriptions
                WHERE session_generation = ?1
                  AND last_delivered_position IS NOT NULL
                  AND last_acked_position IS NOT NULL
                  AND last_delivered_position = last_acked_position
                  AND state = 'live'
            )
            ",
            [generation],
            |row| row.get(0),
        )
        .expect("read resumed replay session")
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
