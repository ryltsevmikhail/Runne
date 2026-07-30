//! Sole owner of the client `SQLite` schema and migrations.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_secure_store::{AnchorStatus, SecureStore, SecureStoreError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Eq, PartialEq)]
pub struct LocalProject {
    pub id: i64,
    pub name: String,
    pub path: PathBuf,
    pub last_opened_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalStoreDiagnostics {
    pub schema_version: u32,
    pub database_generation: u64,
    pub project_count: u64,
}

#[derive(Debug, Error)]
pub enum StoreOpenError {
    #[error("unsupported database schema version: {0}")]
    UnsupportedSchema(i64),
    #[error("legacy replay state cannot be migrated safely")]
    LegacyReplayState,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
}

#[derive(Debug, Error)]
pub enum ProjectOpenError {
    #[error("local project path is not a directory")]
    NotDirectory,
    #[error("local project path has no valid directory name")]
    InvalidName,
    #[error("system clock is before the Unix epoch")]
    InvalidClock,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("local project path cannot be resolved")]
    PathUnavailable(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum SecurityTransactionError {
    #[error("event identity conflict")]
    EventIdentityConflict,
    #[error("mutation identity conflict")]
    MutationIdentityConflict,
    #[error("event generation is out of range")]
    GenerationOutOfRange,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
}

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("database generation is out of range")]
    GenerationOutOfRange,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("secure store unavailable")]
    SecureStore(#[from] SecureStoreError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayScopeKey {
    pub runtime_authority: String,
    pub principal: String,
    pub lineage: String,
    pub scope: String,
    pub binding_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayCheckpoint {
    pub cursor: String,
    pub generation: u64,
    pub event_sequence: u64,
    pub projection_revision: u64,
    pub projection_digest: String,
    pub binding_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredConversationProjection {
    pub payload: Vec<u8>,
    pub revision: u64,
    pub digest: String,
    pub event_sequence: u64,
    pub binding_digest: String,
}

#[derive(Clone, Debug)]
pub struct ReplayTransition<'a> {
    pub scope: &'a ReplayScopeKey,
    pub expected_checkpoint: Option<&'a ReplayCheckpoint>,
    pub event_id: &'a str,
    pub cursor: &'a str,
    pub generation: u64,
    pub event_sequence: u64,
    pub event_bytes: &'a [u8],
    pub event_digest: String,
    pub projection_revision: u64,
    pub projection_bytes: &'a [u8],
    pub projection_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayApplyOutcome {
    Applied { database_generation: u64 },
    AlreadyApplied { database_generation: u64 },
}

#[derive(Debug, Error)]
pub enum ReplayStoreError {
    #[error("replay scope is invalid")]
    InvalidScope,
    #[error("replay digest must be 32-byte lower hex")]
    InvalidDigest,
    #[error("replay cursor must be non-empty")]
    EmptyCursor,
    #[error("stored conversation projection is not valid JSON")]
    CorruptProjectionJson,
    #[error("event digest does not match exact event bytes")]
    EventDigestMismatch,
    #[error("projection digest does not match exact projection bytes")]
    ProjectionDigestMismatch,
    #[error("replay binding does not match stored scope")]
    BindingMismatch,
    #[error("replay cursor does not match stored checkpoint")]
    CursorMismatch,
    #[error("replay generation regressed or does not match stored checkpoint")]
    GenerationMismatch,
    #[error("replay event sequence is not contiguous")]
    NonContiguousSequence,
    #[error("conversation projection revision is not contiguous")]
    NonContiguousRevision,
    #[error("event identity conflict")]
    EventIdentityConflict,
    #[error("replay integer is out of range")]
    IntegerOutOfRange,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
}

#[derive(Clone, Copy, Debug)]
pub struct PreparedMutation<'a> {
    pub runtime_authority: &'a str,
    pub principal: &'a str,
    pub operation_id: &'a str,
    pub idempotency_key: &'a str,
    pub target: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseRecoveryState {
    FirstRun,
    Normal,
    RollbackDetected,
    AdvanceAnchor,
    Ambiguous,
    AnchorMissing,
    DatabaseMissing,
}

#[must_use]
pub const fn classify_database_recovery(
    database_generation: Option<u64>,
    anchor_generation: Option<u64>,
    valid_commit_marker: bool,
) -> DatabaseRecoveryState {
    match (database_generation, anchor_generation) {
        (None, None) => DatabaseRecoveryState::FirstRun,
        (Some(database), Some(anchor)) if database == anchor => DatabaseRecoveryState::Normal,
        (Some(database), Some(anchor)) if database < anchor => {
            DatabaseRecoveryState::RollbackDetected
        }
        (Some(database), Some(anchor))
            if database == anchor.saturating_add(1) && valid_commit_marker =>
        {
            DatabaseRecoveryState::AdvanceAnchor
        }
        (Some(_), Some(_)) => DatabaseRecoveryState::Ambiguous,
        (Some(_), None) => DatabaseRecoveryState::AnchorMissing,
        (None, Some(_)) => DatabaseRecoveryState::DatabaseMissing,
    }
}

pub struct LocalStore {
    connection: Connection,
}

impl LocalStore {
    /// Opens a profile database and applies required migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self, StoreOpenError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            ",
        )?;
        let mut store = Self { connection };
        store.apply_migrations()?;
        Ok(store)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_migrations(&mut self) -> Result<(), StoreOpenError> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > 4 {
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
            transaction.execute_batch(
                "
                DROP TABLE projections;
                DROP TABLE event_journal;
                DROP TABLE replay_cursors;

                CREATE TABLE projections (
                    runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
                    principal TEXT NOT NULL CHECK (length(principal) > 0),
                    lineage TEXT NOT NULL CHECK (length(lineage) > 0),
                    scope TEXT NOT NULL CHECK (length(scope) > 0),
                    binding_digest TEXT NOT NULL CHECK (
                        length(binding_digest) = 64
                        AND binding_digest NOT GLOB '*[^0-9a-f]*'
                    ),
                    projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0),
                    projection_digest TEXT NOT NULL CHECK (
                        length(projection_digest) = 64
                        AND projection_digest NOT GLOB '*[^0-9a-f]*'
                    ),
                    event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
                    payload BLOB NOT NULL CHECK (json_valid(payload) = 1),
                    PRIMARY KEY (runtime_authority, principal, lineage, scope)
                ) STRICT;

                CREATE TABLE event_journal (
                    runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
                    principal TEXT NOT NULL CHECK (length(principal) > 0),
                    lineage TEXT NOT NULL CHECK (length(lineage) > 0),
                    scope TEXT NOT NULL CHECK (length(scope) > 0),
                    binding_digest TEXT NOT NULL CHECK (
                        length(binding_digest) = 64
                        AND binding_digest NOT GLOB '*[^0-9a-f]*'
                    ),
                    event_id TEXT NOT NULL CHECK (length(event_id) > 0),
                    cursor TEXT NOT NULL CHECK (length(cursor) > 0),
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
                    validated_event BLOB NOT NULL,
                    event_digest TEXT NOT NULL CHECK (
                        length(event_digest) = 64
                        AND event_digest NOT GLOB '*[^0-9a-f]*'
                    ),
                    PRIMARY KEY (
                        runtime_authority,
                        principal,
                        lineage,
                        scope,
                        event_id
                    ),
                    UNIQUE (
                        runtime_authority,
                        principal,
                        lineage,
                        scope,
                        event_sequence
                    ),
                    UNIQUE (
                        runtime_authority,
                        principal,
                        lineage,
                        scope,
                        cursor
                    )
                ) STRICT;

                CREATE TABLE replay_cursors (
                    runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
                    principal TEXT NOT NULL CHECK (length(principal) > 0),
                    lineage TEXT NOT NULL CHECK (length(lineage) > 0),
                    scope TEXT NOT NULL CHECK (length(scope) > 0),
                    binding_digest TEXT NOT NULL CHECK (
                        length(binding_digest) = 64
                        AND binding_digest NOT GLOB '*[^0-9a-f]*'
                    ),
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    applied_cursor TEXT NOT NULL CHECK (length(applied_cursor) > 0),
                    event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
                    projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0),
                    projection_digest TEXT NOT NULL CHECK (
                        length(projection_digest) = 64
                        AND projection_digest NOT GLOB '*[^0-9a-f]*'
                    ),
                    PRIMARY KEY (runtime_authority, principal, lineage, scope)
                ) STRICT;

                UPDATE meta SET schema_version = 4 WHERE singleton = 1;
                PRAGMA user_version = 4;
                ",
            )?;
            transaction.commit()?;
        }
        Ok(())
    }

    /// Stores a non-secret string setting.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be committed.
    pub fn set_setting(&mut self, key: &str, value: &str) -> rusqlite::Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "
            INSERT INTO settings (key, value)
            VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                revision = settings.revision + 1
            ",
            params![key, value],
        )?;
        transaction.commit()
    }

    /// Reads a non-secret string setting.
    ///
    /// # Errors
    ///
    /// Returns an error if the query cannot be completed.
    pub fn get_setting(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    /// Persists a validated local directory and returns its stable project row.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is invalid, cannot be resolved, or
    /// the storage transaction cannot be committed.
    pub fn open_local_project(&mut self, path: &Path) -> Result<LocalProject, ProjectOpenError> {
        if !path.is_dir() {
            return Err(ProjectOpenError::NotDirectory);
        }
        let path = path
            .canonicalize()
            .map_err(ProjectOpenError::PathUnavailable)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(ProjectOpenError::InvalidName)?
            .to_owned();
        let last_opened_at = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ProjectOpenError::InvalidClock)?
                .as_millis(),
        )
        .map_err(|_| ProjectOpenError::InvalidClock)?;
        let path_value = path.to_string_lossy();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "
            INSERT INTO projects (name, path, last_opened_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(path) DO UPDATE SET
                name = excluded.name,
                last_opened_at = excluded.last_opened_at
            ",
            params![name, path_value, last_opened_at],
        )?;
        let id = transaction.query_row(
            "SELECT id FROM projects WHERE path = ?1",
            params![path_value],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(LocalProject {
            id,
            name,
            path,
            last_opened_at,
        })
    }

    /// Lists local projects with the most recently opened first.
    ///
    /// # Errors
    ///
    /// Returns an error if the query or stored row cannot be read.
    pub fn list_projects(&self) -> rusqlite::Result<Vec<LocalProject>> {
        let mut statement = self.connection.prepare(
            "
            SELECT id, name, path, last_opened_at
            FROM projects
            ORDER BY last_opened_at DESC, id DESC
            ",
        )?;
        statement
            .query_map([], |row| {
                Ok(LocalProject {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    path: PathBuf::from(row.get::<_, String>(2)?),
                    last_opened_at: row.get(3)?,
                })
            })?
            .collect()
    }

    /// Loads one local project by stable database id.
    ///
    /// # Errors
    ///
    /// Returns an error if the query or stored row cannot be read.
    pub fn get_project(&self, id: i64) -> rusqlite::Result<Option<LocalProject>> {
        self.connection
            .query_row(
                "
                SELECT id, name, path, last_opened_at
                FROM projects
                WHERE id = ?1
                ",
                params![id],
                |row| {
                    Ok(LocalProject {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        path: PathBuf::from(row.get::<_, String>(2)?),
                        last_opened_at: row.get(3)?,
                    })
                },
            )
            .optional()
    }

    /// Returns bounded, path-free local storage diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata or counts cannot be read.
    pub fn diagnostics(&self) -> Result<LocalStoreDiagnostics, SecurityTransactionError> {
        let (schema_version, database_generation): (i64, i64) = self.connection.query_row(
            "
            SELECT schema_version, db_generation
            FROM meta
            WHERE singleton = 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let project_count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?;
        Ok(LocalStoreDiagnostics {
            schema_version: u32::try_from(schema_version)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange)?,
            database_generation: u64::try_from(database_generation)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange)?,
            project_count: u64::try_from(project_count)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange)?,
        })
    }

    /// Reads the durable checkpoint for one stable replay scope.
    ///
    /// # Errors
    ///
    /// Returns a typed integrity error instead of defaulting corrupt or
    /// internally inconsistent replay state.
    pub fn replay_checkpoint(
        &self,
        scope: &ReplayScopeKey,
    ) -> Result<Option<ReplayCheckpoint>, ReplayStoreError> {
        validate_replay_scope(scope)?;
        Ok(read_replay_state(&self.connection, scope)?.map(|state| state.checkpoint))
    }

    /// Reads the verified Conversation projection for one stable replay scope.
    ///
    /// # Errors
    ///
    /// Returns a typed integrity error for invalid JSON, a digest mismatch,
    /// binding mismatch or non-contiguous stored state.
    pub fn conversation_projection(
        &self,
        scope: &ReplayScopeKey,
    ) -> Result<Option<StoredConversationProjection>, ReplayStoreError> {
        validate_replay_scope(scope)?;
        Ok(read_replay_state(&self.connection, scope)?.map(|state| state.projection))
    }

    /// Atomically journals one validated event, replaces its verified
    /// Conversation projection and advances the durable replay checkpoint.
    ///
    /// Exact inclusive redelivery returns [`ReplayApplyOutcome::AlreadyApplied`]
    /// without incrementing the database generation.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, identity or storage error. Any error rolls
    /// back journal, projection, cursor and database generation together.
    #[allow(clippy::too_many_lines)]
    pub fn apply_replay_transition(
        &mut self,
        transition: &ReplayTransition<'_>,
    ) -> Result<ReplayApplyOutcome, ReplayStoreError> {
        validate_replay_transition_shape(transition)?;
        let generation = i64::try_from(transition.generation)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let event_sequence = i64::try_from(transition.event_sequence)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let projection_revision = i64::try_from(transition.projection_revision)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let scope = transition.scope;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<(String, String, i64, i64, Vec<u8>, String)> = transaction
            .query_row(
                "
                SELECT
                    binding_digest,
                    cursor,
                    generation,
                    event_sequence,
                    validated_event,
                    event_digest
                FROM event_journal
                WHERE runtime_authority = ?1
                  AND principal = ?2
                  AND lineage = ?3
                  AND scope = ?4
                  AND event_id = ?5
                ",
                params![
                    scope.runtime_authority,
                    scope.principal,
                    scope.lineage,
                    scope.scope,
                    transition.event_id
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing.0 != scope.binding_digest {
                return Err(ReplayStoreError::BindingMismatch);
            }
            if existing.1 != transition.cursor
                || existing.2 != generation
                || existing.3 != event_sequence
                || existing.4 != transition.event_bytes
                || existing.5 != transition.event_digest
            {
                return Err(ReplayStoreError::EventIdentityConflict);
            }
            read_replay_state(&transaction, scope)?
                .ok_or(ReplayStoreError::NonContiguousRevision)?;
            let database_generation = read_database_generation(&transaction)?;
            transaction.commit()?;
            return Ok(ReplayApplyOutcome::AlreadyApplied {
                database_generation,
            });
        }

        validate_replay_transition_payload(&transaction, transition)?;
        let current = read_replay_state(&transaction, scope)?;
        validate_expected_transition(current.as_ref(), transition)?;

        transaction.execute(
            "
            INSERT INTO event_journal (
                runtime_authority,
                principal,
                lineage,
                scope,
                binding_digest,
                event_id,
                cursor,
                generation,
                event_sequence,
                validated_event,
                event_digest
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ",
            params![
                scope.runtime_authority,
                scope.principal,
                scope.lineage,
                scope.scope,
                scope.binding_digest,
                transition.event_id,
                transition.cursor,
                generation,
                event_sequence,
                transition.event_bytes,
                transition.event_digest
            ],
        )?;
        transaction.execute(
            "
            INSERT INTO projections (
                runtime_authority,
                principal,
                lineage,
                scope,
                binding_digest,
                projection_revision,
                projection_digest,
                event_sequence,
                payload
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(runtime_authority, principal, lineage, scope) DO UPDATE SET
                binding_digest = excluded.binding_digest,
                projection_revision = excluded.projection_revision,
                projection_digest = excluded.projection_digest,
                event_sequence = excluded.event_sequence,
                payload = excluded.payload
            ",
            params![
                scope.runtime_authority,
                scope.principal,
                scope.lineage,
                scope.scope,
                scope.binding_digest,
                projection_revision,
                transition.projection_digest,
                event_sequence,
                transition.projection_bytes
            ],
        )?;
        transaction.execute(
            "
            INSERT INTO replay_cursors (
                runtime_authority,
                principal,
                lineage,
                scope,
                binding_digest,
                generation,
                applied_cursor,
                event_sequence,
                projection_revision,
                projection_digest
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(runtime_authority, principal, lineage, scope) DO UPDATE SET
                binding_digest = excluded.binding_digest,
                generation = excluded.generation,
                applied_cursor = excluded.applied_cursor,
                event_sequence = excluded.event_sequence,
                projection_revision = excluded.projection_revision,
                projection_digest = excluded.projection_digest
            ",
            params![
                scope.runtime_authority,
                scope.principal,
                scope.lineage,
                scope.scope,
                scope.binding_digest,
                generation,
                transition.cursor,
                event_sequence,
                projection_revision,
                transition.projection_digest
            ],
        )?;
        transaction.execute(
            "
            UPDATE meta
            SET db_generation = db_generation + 1,
                last_transaction_digest = ?1,
                commit_marker = 1
            WHERE singleton = 1
            ",
            params![transition.event_digest],
        )?;
        let database_generation = read_database_generation(&transaction)?;
        transaction.commit()?;
        Ok(ReplayApplyOutcome::Applied {
            database_generation,
        })
    }

    /// Persists a prepared mutation before any external dispatch.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict if an operation or idempotency identity is
    /// rebound, or a storage error when the transaction cannot commit.
    #[allow(clippy::too_many_lines)]
    pub fn prepare_mutation(
        &mut self,
        mutation: &PreparedMutation<'_>,
    ) -> Result<u64, SecurityTransactionError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String, String, String)> = transaction
            .query_row(
                "
                SELECT
                    runtime_authority,
                    principal,
                    operation_id,
                    idempotency_key,
                    target
                FROM mutation_ledger
                WHERE (runtime_authority = ?1 AND principal = ?2 AND operation_id = ?3)
                   OR (runtime_authority = ?1 AND principal = ?2 AND idempotency_key = ?4)
                ",
                params![
                    mutation.runtime_authority,
                    mutation.principal,
                    mutation.operation_id,
                    mutation.idempotency_key
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            let expected = (
                mutation.runtime_authority,
                mutation.principal,
                mutation.operation_id,
                mutation.idempotency_key,
                mutation.target,
            );
            if (
                existing.0.as_str(),
                existing.1.as_str(),
                existing.2.as_str(),
                existing.3.as_str(),
                existing.4.as_str(),
            ) != expected
            {
                return Err(SecurityTransactionError::MutationIdentityConflict);
            }
            let generation: i64 = transaction.query_row(
                "SELECT db_generation FROM meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            transaction.commit()?;
            return u64::try_from(generation)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange);
        }

        transaction.execute(
            "
            INSERT INTO mutation_ledger (
                runtime_authority,
                principal,
                operation_id,
                idempotency_key,
                target,
                disposition
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 'prepared')
            ",
            params![
                mutation.runtime_authority,
                mutation.principal,
                mutation.operation_id,
                mutation.idempotency_key,
                mutation.target
            ],
        )?;
        let mut hasher = Sha256::new();
        for field in [
            mutation.runtime_authority,
            mutation.principal,
            mutation.operation_id,
            mutation.idempotency_key,
            mutation.target,
        ] {
            hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        let digest = format!("{:x}", hasher.finalize());
        transaction.execute(
            "
            UPDATE meta
            SET db_generation = db_generation + 1,
                last_transaction_digest = ?1,
                commit_marker = 1
            WHERE singleton = 1
            ",
            params![digest],
        )?;
        let database_generation: i64 = transaction.query_row(
            "SELECT db_generation FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        u64::try_from(database_generation)
            .map_err(|_| SecurityTransactionError::GenerationOutOfRange)
    }
}

struct VerifiedReplayState {
    checkpoint: ReplayCheckpoint,
    projection: StoredConversationProjection,
}

#[allow(clippy::too_many_lines)]
fn read_replay_state(
    connection: &Connection,
    scope: &ReplayScopeKey,
) -> Result<Option<VerifiedReplayState>, ReplayStoreError> {
    type StoredRow = (
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<Vec<u8>>,
        i64,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<i64>,
        i64,
    );
    let row: Option<StoredRow> = connection
        .query_row(
            "
            SELECT
                cursors.binding_digest,
                cursors.generation,
                cursors.applied_cursor,
                cursors.event_sequence,
                cursors.projection_revision,
                cursors.projection_digest,
                projections.binding_digest,
                projections.projection_revision,
                projections.projection_digest,
                projections.event_sequence,
                projections.payload,
                (
                    SELECT COUNT(*)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                ),
                (
                    SELECT MIN(event_sequence)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                ),
                (
                    SELECT MAX(event_sequence)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                ),
                (
                    SELECT cursor
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                    ORDER BY event_sequence DESC
                    LIMIT 1
                ),
                (
                    SELECT generation
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                    ORDER BY event_sequence DESC
                    LIMIT 1
                ),
                (
                    SELECT COUNT(*)
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
                      AND journal.binding_digest != ?5
                )
            FROM (SELECT 1) AS seed
            LEFT JOIN replay_cursors AS cursors
              ON cursors.runtime_authority = ?1
             AND cursors.principal = ?2
             AND cursors.lineage = ?3
             AND cursors.scope = ?4
            LEFT JOIN projections
              ON projections.runtime_authority = ?1
             AND projections.principal = ?2
             AND projections.lineage = ?3
             AND projections.scope = ?4
            WHERE cursors.scope IS NOT NULL
               OR projections.scope IS NOT NULL
               OR EXISTS (
                    SELECT 1
                    FROM event_journal AS journal
                    WHERE journal.runtime_authority = ?1
                      AND journal.principal = ?2
                      AND journal.lineage = ?3
                      AND journal.scope = ?4
               )
            ",
            params![
                scope.runtime_authority,
                scope.principal,
                scope.lineage,
                scope.scope,
                scope.binding_digest
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let (
        Some(cursor_binding),
        Some(generation),
        Some(cursor),
        Some(cursor_sequence),
        Some(cursor_revision),
        Some(cursor_projection_digest),
        Some(projection_binding),
        Some(projection_revision),
        Some(projection_digest),
        Some(projection_sequence),
        Some(payload),
        journal_count,
        journal_min_sequence,
        journal_max_sequence,
        latest_journal_cursor,
        latest_journal_generation,
        journal_binding_mismatches,
    ) = row
    else {
        return Err(ReplayStoreError::NonContiguousRevision);
    };
    if cursor_binding != scope.binding_digest
        || projection_binding != scope.binding_digest
        || cursor_binding != projection_binding
        || journal_binding_mismatches != 0
    {
        return Err(ReplayStoreError::BindingMismatch);
    }
    if !is_lower_hex_digest(&cursor_projection_digest) || !is_lower_hex_digest(&projection_digest) {
        return Err(ReplayStoreError::InvalidDigest);
    }
    if cursor_revision != projection_revision {
        return Err(ReplayStoreError::NonContiguousRevision);
    }
    if cursor_projection_digest != projection_digest {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }
    if cursor_sequence != projection_sequence {
        return Err(ReplayStoreError::NonContiguousSequence);
    }
    let generation = u64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    let event_sequence =
        u64::try_from(cursor_sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    let projection_revision =
        u64::try_from(cursor_revision).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    let journal_count =
        u64::try_from(journal_count).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
    if projection_revision == 0 || projection_revision != event_sequence {
        return Err(ReplayStoreError::NonContiguousRevision);
    }
    if event_sequence == 0
        || journal_count != event_sequence
        || journal_min_sequence != Some(1)
        || journal_max_sequence != Some(cursor_sequence)
        || latest_journal_cursor.as_deref() != Some(cursor.as_str())
        || latest_journal_generation
            != Some(i64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?)
    {
        return Err(ReplayStoreError::NonContiguousSequence);
    }
    let valid_json: i64 =
        connection.query_row("SELECT json_valid(?1)", params![payload], |row| row.get(0))?;
    if valid_json != 1 {
        return Err(ReplayStoreError::CorruptProjectionJson);
    }
    if sha256_lower_hex(&payload) != projection_digest {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }

    Ok(Some(VerifiedReplayState {
        checkpoint: ReplayCheckpoint {
            cursor,
            generation,
            event_sequence,
            projection_revision,
            projection_digest: projection_digest.clone(),
            binding_digest: cursor_binding,
        },
        projection: StoredConversationProjection {
            payload,
            revision: projection_revision,
            digest: projection_digest,
            event_sequence,
            binding_digest: projection_binding,
        },
    }))
}

fn validate_replay_scope(scope: &ReplayScopeKey) -> Result<(), ReplayStoreError> {
    if scope.runtime_authority.is_empty()
        || scope.principal.is_empty()
        || scope.lineage.is_empty()
        || scope.scope.is_empty()
    {
        return Err(ReplayStoreError::InvalidScope);
    }
    if !is_lower_hex_digest(&scope.binding_digest) {
        return Err(ReplayStoreError::InvalidDigest);
    }
    Ok(())
}

fn validate_replay_transition_shape(
    transition: &ReplayTransition<'_>,
) -> Result<(), ReplayStoreError> {
    validate_replay_scope(transition.scope)?;
    if transition.event_id.is_empty() {
        return Err(ReplayStoreError::InvalidScope);
    }
    if transition.cursor.is_empty() {
        return Err(ReplayStoreError::EmptyCursor);
    }
    if !is_lower_hex_digest(&transition.event_digest)
        || !is_lower_hex_digest(&transition.projection_digest)
    {
        return Err(ReplayStoreError::InvalidDigest);
    }
    if transition.event_sequence == 0 {
        return Err(ReplayStoreError::NonContiguousSequence);
    }
    if transition.projection_revision == 0 {
        return Err(ReplayStoreError::NonContiguousRevision);
    }
    Ok(())
}

fn validate_replay_transition_payload(
    connection: &Connection,
    transition: &ReplayTransition<'_>,
) -> Result<(), ReplayStoreError> {
    if sha256_lower_hex(transition.event_bytes) != transition.event_digest {
        return Err(ReplayStoreError::EventDigestMismatch);
    }
    if sha256_lower_hex(transition.projection_bytes) != transition.projection_digest {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }
    let valid_json: i64 = connection.query_row(
        "SELECT json_valid(?1)",
        params![transition.projection_bytes],
        |row| row.get(0),
    )?;
    if valid_json != 1 {
        return Err(ReplayStoreError::CorruptProjectionJson);
    }
    Ok(())
}

fn validate_expected_transition(
    current: Option<&VerifiedReplayState>,
    transition: &ReplayTransition<'_>,
) -> Result<(), ReplayStoreError> {
    match (current, transition.expected_checkpoint) {
        (None, None) => {
            if transition.event_sequence != 1 {
                return Err(ReplayStoreError::NonContiguousSequence);
            }
            if transition.projection_revision != 1 {
                return Err(ReplayStoreError::NonContiguousRevision);
            }
        }
        (None, Some(_)) | (Some(_), None) => return Err(ReplayStoreError::CursorMismatch),
        (Some(current), Some(expected)) => {
            let checkpoint = &current.checkpoint;
            if expected.binding_digest != transition.scope.binding_digest
                || expected.binding_digest != checkpoint.binding_digest
            {
                return Err(ReplayStoreError::BindingMismatch);
            }
            if expected.cursor != checkpoint.cursor {
                return Err(ReplayStoreError::CursorMismatch);
            }
            if expected.generation != checkpoint.generation {
                return Err(ReplayStoreError::GenerationMismatch);
            }
            if expected.event_sequence != checkpoint.event_sequence {
                return Err(ReplayStoreError::NonContiguousSequence);
            }
            if expected.projection_revision != checkpoint.projection_revision {
                return Err(ReplayStoreError::NonContiguousRevision);
            }
            if expected.projection_digest != checkpoint.projection_digest {
                return Err(ReplayStoreError::ProjectionDigestMismatch);
            }
            if transition.cursor == checkpoint.cursor {
                return Err(ReplayStoreError::CursorMismatch);
            }
            if transition.generation < checkpoint.generation {
                return Err(ReplayStoreError::GenerationMismatch);
            }
            if checkpoint.event_sequence.checked_add(1) != Some(transition.event_sequence) {
                return Err(ReplayStoreError::NonContiguousSequence);
            }
            if checkpoint.projection_revision.checked_add(1) != Some(transition.projection_revision)
            {
                return Err(ReplayStoreError::NonContiguousRevision);
            }
        }
    }
    Ok(())
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn sha256_lower_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_database_generation(connection: &Connection) -> Result<u64, ReplayStoreError> {
    let generation: i64 = connection.query_row(
        "SELECT db_generation FROM meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    u64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)
}

/// Verifies the relationship between the `SQLite` `db_generation` and the
/// OS secure-store anchor. Returns the classified state per
/// `CLIENT_STORAGE_AND_RECOVERY.md` recovery state machine.
///
/// # Errors
///
/// Returns an error if the database cannot be read or the secure store
/// is unavailable.
pub fn verify_anchor(
    store: &LocalStore,
    secure_store: &dyn SecureStore,
) -> Result<AnchorStatus, AnchorError> {
    let (db_gen, valid_commit_marker) = store.get_anchor_evidence()?;
    let anchor = secure_store.read_anchor()?;

    Ok(match anchor {
        None => AnchorStatus::AnchorMissing { db_gen },
        Some(a) if db_gen == a => AnchorStatus::Normal,
        Some(a) if db_gen < a => AnchorStatus::DbLowerThanAnchor { db_gen, anchor: a },
        Some(a) if a.checked_add(1) == Some(db_gen) && valid_commit_marker => {
            AnchorStatus::DbOneAhead { db_gen, anchor: a }
        }
        Some(a) => AnchorStatus::DbTooFarAhead { db_gen, anchor: a },
    })
}

/// Stores the current `db_generation` as an OS secure-store anchor.
///
/// # Errors
///
/// Returns an error if the database cannot be read or the secure store
/// write fails.
pub fn anchor_db_generation(
    store: &LocalStore,
    secure_store: &dyn SecureStore,
) -> Result<(), AnchorError> {
    secure_store.store_anchor(store.get_db_generation()?)?;
    Ok(())
}

impl LocalStore {
    /// Returns the current `db_generation` from the meta table.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be read or the stored generation
    /// cannot be represented as an unsigned integer.
    pub fn get_db_generation(&self) -> Result<u64, AnchorError> {
        let generation: i64 = self.connection.query_row(
            "SELECT db_generation FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(generation).map_err(|_| AnchorError::GenerationOutOfRange)
    }

    fn get_anchor_evidence(&self) -> Result<(u64, bool), AnchorError> {
        let (generation, commit_marker): (i64, i64) = self.connection.query_row(
            "SELECT db_generation, commit_marker FROM meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let generation =
            u64::try_from(generation).map_err(|_| AnchorError::GenerationOutOfRange)?;
        Ok((generation, commit_marker == 1))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseRecoveryState, LocalStore, PreparedMutation, anchor_db_generation,
        classify_database_recovery, verify_anchor,
    };
    use gocode_secure_store::{AnchorStatus, SecureStore, SecureStoreError};
    use rusqlite::Connection;
    use std::path::Path;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemorySecureStore {
        anchor: Mutex<Option<u64>>,
    }

    impl SecureStore for MemorySecureStore {
        fn store_anchor(&self, generation: u64) -> Result<(), SecureStoreError> {
            *self.anchor.lock().expect("anchor lock") = Some(generation);
            Ok(())
        }

        fn read_anchor(&self) -> Result<Option<u64>, SecureStoreError> {
            Ok(*self.anchor.lock().expect("anchor lock"))
        }

        fn delete_anchor(&self) -> Result<(), SecureStoreError> {
            *self.anchor.lock().expect("anchor lock") = None;
            Ok(())
        }
    }

    #[test]
    fn anchors_current_database_generation_and_verifies_normal_state() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        let store = LocalStore::open(&path).expect("open store");
        let secure_store = MemorySecureStore::default();

        anchor_db_generation(&store, &secure_store).expect("anchor generation");

        assert_eq!(secure_store.read_anchor().expect("read anchor"), Some(1));
        assert_eq!(
            verify_anchor(&store, &secure_store).expect("verify anchor"),
            AnchorStatus::Normal
        );
    }

    #[test]
    fn database_one_ahead_requires_a_valid_commit_marker() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        let store = LocalStore::open(&path).expect("open store");
        let secure_store = MemorySecureStore {
            anchor: Mutex::new(Some(1)),
        };
        store
            .connection
            .execute(
                "UPDATE meta SET db_generation = 2, commit_marker = 0 WHERE singleton = 1",
                [],
            )
            .expect("set unverified generation");

        assert_eq!(
            verify_anchor(&store, &secure_store).expect("verify anchor"),
            AnchorStatus::DbTooFarAhead {
                db_gen: 2,
                anchor: 1,
            }
        );

        store
            .connection
            .execute("UPDATE meta SET commit_marker = 1 WHERE singleton = 1", [])
            .expect("set valid commit marker");

        assert_eq!(
            verify_anchor(&store, &secure_store).expect("verify anchor"),
            AnchorStatus::DbOneAhead {
                db_gen: 2,
                anchor: 1,
            }
        );
    }

    #[test]
    fn persists_settings_across_reopen() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");

        {
            let mut store = LocalStore::open(&path).expect("open store");
            store
                .set_setting("appearance.theme", "light")
                .expect("save setting");
        }

        let store = LocalStore::open(&path).expect("reopen store");
        assert_eq!(
            Some("light".to_owned()),
            store.get_setting("appearance.theme").expect("read setting")
        );
    }

    #[test]
    fn persists_local_projects_and_reopens_the_most_recent_workspace() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("alpha");
        std::fs::create_dir(&project_path).expect("create project directory");
        let canonical_project_path = project_path.canonicalize().expect("canonical project path");

        let project_id = {
            let mut store = LocalStore::open(&path).expect("open store");
            store
                .open_local_project(&project_path)
                .expect("persist local project")
                .id
        };

        let store = LocalStore::open(&path).expect("reopen store");
        let projects = store.list_projects().expect("list projects");

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, project_id);
        assert_eq!(projects[0].name, "alpha");
        assert_eq!(projects[0].path, canonical_project_path);
        assert_eq!(
            store
                .get_project(project_id)
                .expect("load project")
                .expect("stored project")
                .path,
            canonical_project_path
        );
    }

    #[test]
    fn rejects_a_local_project_path_that_is_not_a_directory() {
        let directory = tempfile::tempdir().expect("temp directory");
        let mut store =
            LocalStore::open(&directory.path().join("profile.sqlite3")).expect("open store");

        let error = store
            .open_local_project(Path::new("missing-project"))
            .expect_err("missing path must be rejected");

        assert_eq!(error.to_string(), "local project path is not a directory");
        assert!(store.list_projects().expect("list projects").is_empty());
    }

    #[test]
    fn rejects_a_future_schema_version_without_rewriting_it() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        let connection = Connection::open(&path).expect("create database");
        connection
            .pragma_update(None, "user_version", 99)
            .expect("set future schema");
        drop(connection);

        let Err(error) = LocalStore::open(&path) else {
            panic!("future schema must be rejected");
        };

        assert_eq!(error.to_string(), "unsupported database schema version: 99");
        let connection = Connection::open(path).expect("reopen database");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read schema version");
        assert_eq!(version, 99);
    }

    #[test]
    fn migration_v4_creates_the_normative_recovery_schema() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");

        LocalStore::open(&path).expect("open and migrate store");

        let connection = Connection::open(path).expect("inspect database");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read schema version");
        assert_eq!(version, 4);

        for table in [
            "meta",
            "drafts",
            "projections",
            "event_journal",
            "replay_cursors",
            "mutation_ledger",
            "window_layout",
        ] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get(0),
                )
                .expect("inspect table");
            assert!(exists, "missing table {table}");
        }

        let generation: i64 = connection
            .query_row(
                "SELECT db_generation FROM meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read database generation");
        assert_eq!(generation, 1);
    }

    #[test]
    fn classifies_every_documented_database_anchor_state() {
        use DatabaseRecoveryState::{
            AdvanceAnchor, Ambiguous, AnchorMissing, DatabaseMissing, FirstRun, Normal,
            RollbackDetected,
        };

        assert_eq!(classify_database_recovery(None, None, false), FirstRun);
        assert_eq!(classify_database_recovery(Some(4), Some(4), false), Normal);
        assert_eq!(
            classify_database_recovery(Some(3), Some(4), false),
            RollbackDetected
        );
        assert_eq!(
            classify_database_recovery(Some(5), Some(4), true),
            AdvanceAnchor
        );
        assert_eq!(
            classify_database_recovery(Some(5), Some(4), false),
            Ambiguous
        );
        assert_eq!(
            classify_database_recovery(Some(7), Some(4), true),
            Ambiguous
        );
        assert_eq!(
            classify_database_recovery(Some(4), None, false),
            AnchorMissing
        );
        assert_eq!(
            classify_database_recovery(None, Some(4), false),
            DatabaseMissing
        );
    }

    #[test]
    fn prepared_mutation_is_durable_idempotent_and_identity_bound() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open(&path).expect("open store");
        let mutation = PreparedMutation {
            runtime_authority: "runtime-1",
            principal: "user-1",
            operation_id: "operation-1",
            idempotency_key: "idempotency-1",
            target: "workspace-1",
        };

        assert_eq!(store.prepare_mutation(&mutation).expect("prepare"), 2);
        assert_eq!(
            store
                .prepare_mutation(&mutation)
                .expect("prepare duplicate"),
            2
        );

        let conflicting = PreparedMutation {
            target: "workspace-2",
            ..mutation
        };
        let error = store
            .prepare_mutation(&conflicting)
            .expect_err("identity conflict");
        assert_eq!(error.to_string(), "mutation identity conflict");

        let connection = Connection::open(path).expect("inspect database");
        let (count, generation): (i64, i64) = connection
            .query_row(
                "
                SELECT COUNT(*), meta.db_generation
                FROM mutation_ledger CROSS JOIN meta
                WHERE meta.singleton = 1
                ",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read ledger");
        assert_eq!(count, 1);
        assert_eq!(generation, 2);
    }
}
