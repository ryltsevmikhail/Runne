// Execution nodes may be registered by the local darwin runtime as well as
// Linux. The original v41 table hard-coded `platform = 'linux'`. New databases
// are created with the wider check; existing v71 databases are repaired in
// place, preserving every row, trigger and the schema version marker.

pub(super) const MIGRATION_V72: &str = r#"
CREATE TABLE execution_nodes (
    node_id BLOB PRIMARY KEY CHECK(length(node_id) = 16 AND node_id != zeroblob(16)),
    launch_generation INTEGER NOT NULL CHECK(launch_generation > 0),
    descriptor_version INTEGER NOT NULL CHECK(descriptor_version = 1),
    platform TEXT NOT NULL CHECK(platform IN ('linux','darwin')),
    executor_protocol TEXT NOT NULL CHECK(executor_protocol = 'runne-taskrun-v1'),
    workspace_backend TEXT NOT NULL CHECK(workspace_backend = 'git-worktree-v1'),
    capacity INTEGER NOT NULL CHECK(capacity > 0 AND capacity <= 4294967295),
    heartbeat_at_ms INTEGER NOT NULL CHECK(heartbeat_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > heartbeat_at_ms)
);
"#;

const V72_OLD_PLATFORM: &str = "platform TEXT NOT NULL CHECK(platform = 'linux')";
const V72_NEW_PLATFORM: &str = "platform TEXT NOT NULL CHECK(platform IN ('linux','darwin'))";

/// Widens the execution-node platform check on an existing v71 database.
///
/// This is a shape repair, not a versioned schema change: the v41 matcher
/// accepts both the historical and the widened table.
pub(super) fn repair_execution_node_platform(connection: &Connection) -> SqliteResult<()> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='execution_nodes'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(actual) = actual else {
        return Ok(());
    };
    if !actual.contains(V72_OLD_PLATFORM) {
        return Ok(());
    }
    connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    let result = (|| {
        let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
        rebuild_table(
            &tx,
            "execution_nodes",
            V72_OLD_PLATFORM,
            V72_NEW_PLATFORM,
        )?;
        if !v71_matches(&tx, 71)? {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let violated: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )?;
        if violated {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.commit()
    })();
    let restore =
        connection.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;");
    result.and(restore)
}
