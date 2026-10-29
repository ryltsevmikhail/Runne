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
const V72_REPAIR_POSTCONDITION: &str = "execution_nodes platform repair postcondition failed";
const EXECUTION_NODE_FENCE_OPERATIONS: [&str; 3] = ["insert", "update", "delete"];

/// Row contents and version markers captured immediately before the repair.
struct ExecutionNodeState {
    rows: Vec<String>,
    versions: Vec<i64>,
}

/// Widens the execution-node platform check on an existing v71 database.
///
/// This is a shape repair, not a versioned schema change: the v41 matcher
/// accepts both the historical and the widened table. The postcondition only
/// covers what the rebuild can change; the full historical catalog matcher is
/// deliberately not used here because unrelated legacy drift must not turn a
/// successful repair into a failed database open.
pub(super) fn repair_execution_node_platform(connection: &Connection) -> SqliteResult<()> {
    let Some(actual) = execution_node_sql(connection)? else {
        return Ok(());
    };
    if !normalized_contains(&actual, V72_OLD_PLATFORM) {
        return Ok(());
    }
    let before = execution_node_state(connection)?;
    connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    let result = (|| {
        let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
        rebuild_table(&tx, "execution_nodes", V72_OLD_PLATFORM, V72_NEW_PLATFORM)?;
        verify_repair_postcondition(&tx, &before)?;
        tx.commit()
    })();
    let restore =
        connection.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;");
    result.and(restore)
}

fn verify_repair_postcondition(
    connection: &Connection,
    before: &ExecutionNodeState,
) -> SqliteResult<()> {
    let table = execution_node_sql(connection)?;
    let expected = MIGRATION_V72
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with("CREATE TABLE execution_nodes "))
        .expect("V72 execution-node DDL is frozen");
    if table.is_none_or(|table| normalize_ddl(&table) != normalize_ddl(expected)) {
        return Err(repair_failure("execution_nodes DDL was not widened"));
    }
    let after = execution_node_state(connection)?;
    if after.rows != before.rows {
        return Err(repair_failure("execution_nodes rows changed"));
    }
    if after.versions != before.versions {
        return Err(repair_failure("schema_version changed"));
    }
    if !execution_node_fences_match(connection)? {
        return Err(repair_failure("execution_nodes fence triggers changed"));
    }
    let violated: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |row| row.get(0),
    )?;
    if violated {
        return Err(repair_failure("foreign_key_check is not empty"));
    }
    Ok(())
}

fn execution_node_state(connection: &Connection) -> SqliteResult<ExecutionNodeState> {
    let rows = connection
        .prepare(
            "SELECT hex(node_id)||'|'||launch_generation||'|'||descriptor_version||'|'||
                    platform||'|'||executor_protocol||'|'||workspace_backend||'|'||
                    capacity||'|'||heartbeat_at_ms||'|'||expires_at_ms
             FROM execution_nodes ORDER BY node_id",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    let versions = connection
        .prepare("SELECT version FROM schema_version ORDER BY version")?
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(ExecutionNodeState { rows, versions })
}

fn execution_node_sql(connection: &Connection) -> SqliteResult<Option<String>> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='execution_nodes'",
            [],
            |row| row.get(0),
        )
        .optional()
}

fn execution_node_fences_match(connection: &Connection) -> SqliteResult<bool> {
    for operation in EXECUTION_NODE_FENCE_OPERATIONS {
        let (name, expected) = v12_fence_trigger("execution_nodes", operation);
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [&name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|actual| normalize_ddl(&actual) != normalize_ddl(&expected)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Postcondition failures are repair failures, never `InvalidQuery`, so the
/// daemon reports which invariant broke instead of "Query is not read-only".
fn repair_failure(detail: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
        Some(format!("{V72_REPAIR_POSTCONDITION}: {detail}")),
    )
}
