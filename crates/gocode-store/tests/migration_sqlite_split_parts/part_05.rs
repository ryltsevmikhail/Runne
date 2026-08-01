fn migration_durable_counts(connection: &Connection) -> [i64; 7] {
    [
        row_count(connection, "migration_plans"),
        row_count(connection, "migration_transitions"),
        row_count(connection, "migration_evidence"),
        row_count(connection, "routing_snapshots"),
        row_count(connection, "routing_head"),
        row_count(connection, "migration_receipts"),
        row_count(connection, "migration_audit"),
    ]
}

fn row_count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self {
            path: std::env::temp_dir().join(format!(
                "gocode-migration-{name}-{}-{nonce}.sqlite",
                std::process::id()
            )),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

#[derive(Clone, Copy)]
struct PureShadow;

impl ShadowExecutionPort for PureShadow {
    fn evaluate(
        &self,
        _input: SanitizedShadowInput,
    ) -> Result<ShadowDiffReport, ShadowExecutionError> {
        Err(ShadowExecutionError::InvalidInput)
    }
}
