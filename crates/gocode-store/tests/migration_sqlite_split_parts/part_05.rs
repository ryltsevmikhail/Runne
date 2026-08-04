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
    database: validated_reopen::ValidatedTestDatabase,
    identity: validated_reopen::MainDatabaseIdentity,
}

impl TempDb {
    fn new(name: &str) -> Self {
        let database = validated_reopen::ValidatedTestDatabase::new(name);
        let identity = validated_reopen::initialize_database_identity(database.path()).unwrap();
        Self { database, identity }
    }

    fn path(&self) -> &Path {
        Path::new(self.database.path())
    }

    fn adopt(&self) -> SqliteMigrationControlStore {
        let connection = validated_reopen::open_validated_connection(self.database.path(), self.identity)
            .unwrap();
        SqliteMigrationControlStore::open_with_connection(self.database.path(), connection).unwrap()
    }

    fn reader(&self) -> Connection {
        let connection = validated_reopen::open_validated_connection(self.database.path(), self.identity)
            .unwrap();
        connection.execute_batch("PRAGMA query_only = ON;").unwrap();
        connection
    }

    fn writer(&self) -> Connection {
        validated_reopen::open_validated_connection(self.database.path(), self.identity).unwrap()
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
