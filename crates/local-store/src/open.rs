use super::{
    Connection, LocalStore, Path, REPLAY_TABLES_V4_SQL, StoreOpenError, TransactionBehavior,
};

impl LocalStore {
    /// Opens or creates the local store and applies the validated migrations.
    ///
    /// # Errors
    ///
    /// Returns a typed open or migration error when the path, schema, or owner
    /// private state cannot be admitted.
    pub fn open(path: &Path) -> Result<Self, StoreOpenError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            ",
        )?;
        let mut store = Self {
            connection,
            security: None,
        };
        store.apply_migrations()?;
        Ok(store)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_migrations(&mut self) -> Result<(), StoreOpenError> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > 5 {
            return Err(StoreOpenError::UnsupportedSchema(version));
        }
        if version < 1 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "
                CREATE TABLE settings (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1
                ) STRICT;
                PRAGMA user_version = 1;
                ",
            )?;
            transaction.commit()?;
        }
        if version < 2 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "
                CREATE TABLE projects (
                    id INTEGER PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    last_opened_at INTEGER NOT NULL
                ) STRICT;
                PRAGMA user_version = 2;
                ",
            )?;
            transaction.commit()?;
        }
        if version < 3 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "
                CREATE TABLE meta (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                    db_generation INTEGER NOT NULL CHECK (db_generation >= 1),
                    last_transaction_digest TEXT,
                    commit_marker INTEGER NOT NULL DEFAULT 0 CHECK (commit_marker IN (0, 1))
                ) STRICT;

                INSERT INTO meta (singleton, schema_version, db_generation)
                VALUES (1, 3, 1);

                CREATE TABLE drafts (
                    runtime_authority TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 1),
                    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
                    PRIMARY KEY (runtime_authority, principal, project_id, run_id)
                ) STRICT;

                CREATE TABLE projections (
                    runtime_authority TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    lineage TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    cursor TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    PRIMARY KEY (runtime_authority, principal, lineage, scope)
                ) STRICT;

                CREATE TABLE event_journal (
                    runtime_authority TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    lineage TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    cursor TEXT NOT NULL,
                    validated_envelope BLOB NOT NULL,
                    digest TEXT NOT NULL,
                    PRIMARY KEY (
                        runtime_authority,
                        principal,
                        lineage,
                        scope,
                        event_id
                    )
                ) STRICT;

                CREATE TABLE replay_cursors (
                    runtime_authority TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    lineage TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    applied_cursor TEXT NOT NULL,
                    PRIMARY KEY (runtime_authority, principal, lineage, scope)
                ) STRICT;

                CREATE TABLE mutation_ledger (
                    runtime_authority TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    target TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    PRIMARY KEY (runtime_authority, principal, operation_id),
                    UNIQUE (runtime_authority, principal, idempotency_key)
                ) STRICT;

                CREATE TABLE window_layout (
                    profile TEXT NOT NULL,
                    display_topology TEXT NOT NULL,
                    geometry TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 1),
                    PRIMARY KEY (profile, display_topology)
                ) STRICT;

                PRAGMA user_version = 3;
                ",
            )?;
            transaction.commit()?;
        }
        if version < 4 {
            self.ensure_pre_v4_migration_backup()?;
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let legacy_replay_rows: i64 = transaction.query_row(
                "
                SELECT
                    (SELECT COUNT(*) FROM projections)
                  + (SELECT COUNT(*) FROM event_journal)
                  + (SELECT COUNT(*) FROM replay_cursors)
                ",
                [],
                |row| row.get(0),
            )?;
            if legacy_replay_rows != 0 {
                return Err(StoreOpenError::LegacyReplayState);
            }
            transaction.execute_batch(REPLAY_TABLES_V4_SQL)?;
            transaction.execute_batch(
                "
                UPDATE meta SET schema_version = 4 WHERE singleton = 1;
                PRAGMA user_version = 4;
                ",
            )?;
            transaction.commit()?;
        }
        if version == 4 {
            let projection_identity_columns: i64 = self.connection.query_row(
                "
                SELECT COUNT(*)
                FROM pragma_table_info('event_journal')
                WHERE name IN (
                    'projection_revision',
                    'projection_digest',
                    'projected_payload'
                )
                ",
                [],
                |row| row.get(0),
            )?;
            if projection_identity_columns != 3 {
                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let replay_tables: i64 = transaction.query_row(
                    "
                    SELECT COUNT(*)
                    FROM sqlite_schema
                    WHERE type = 'table'
                      AND name IN ('projections', 'event_journal', 'replay_cursors')
                    ",
                    [],
                    |row| row.get(0),
                )?;
                if replay_tables != 3 {
                    return Err(StoreOpenError::LegacyReplayState);
                }
                let replay_rows: i64 = transaction.query_row(
                    "
                    SELECT
                        (SELECT COUNT(*) FROM projections)
                      + (SELECT COUNT(*) FROM event_journal)
                      + (SELECT COUNT(*) FROM replay_cursors)
                    ",
                    [],
                    |row| row.get(0),
                )?;
                if replay_rows != 0 {
                    return Err(StoreOpenError::LegacyReplayState);
                }
                transaction.execute_batch(REPLAY_TABLES_V4_SQL)?;
                transaction.commit()?;
            }
        }
        if version < 5 {
            let backup = self.ensure_pre_v5_migration_backup()?;
            self.migrate_v4_recent_roots(backup)?;
        }
        self.validate_v5_schema()?;
        Ok(())
    }
}
