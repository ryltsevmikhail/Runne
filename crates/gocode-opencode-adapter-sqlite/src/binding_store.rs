//! Fail-closed SQLite implementation of `SessionBindingStore`.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_api::{NonNegativeUnixMillis, OpenCodeSessionInfo};
use gocode_domain::id::ConversationId;
use gocode_opencode_compat::{
    BindingError, BindingRuntimeAuthorityId, EnsurePendingResult, MAX_RECOVERY_PENDING_LIMIT,
    SessionBindingContext, SessionBindingKey, SessionBindingStatus, SessionBindingStore,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::codec::{
    CODEC_VERSION, decode_context, decode_response, encode_context, encode_response,
};
use crate::schema::{apply_migrations_and_verify, harden_permissions, open_with_pragmas};

/// Fallible source of durable creation timestamps.
pub trait BindingClock: Send + Sync {
    /// Returns a non-negative Unix timestamp in milliseconds.
    fn now_millis(&self) -> Result<NonNegativeUnixMillis, BindingError>;
}

/// Production clock backed by `SystemTime` without silent fallbacks.
#[derive(Debug, Default)]
pub struct SystemBindingClock;

impl BindingClock for SystemBindingClock {
    fn now_millis(&self) -> Result<NonNegativeUnixMillis, BindingError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BindingError::StorageFailure)?;
        let millis =
            i64::try_from(duration.as_millis()).map_err(|_| BindingError::StorageFailure)?;
        NonNegativeUnixMillis::new(millis).ok_or(BindingError::StorageFailure)
    }
}

struct Inner {
    conn: Mutex<Connection>,
    clock: Arc<dyn BindingClock>,
    path: Option<PathBuf>,
}

/// A single-writer, durable SQLite session-binding store.
#[derive(Clone)]
pub struct SqliteSessionBindingStore {
    inner: Arc<Inner>,
}

impl SqliteSessionBindingStore {
    /// Opens and verifies a durable binding database using the production clock.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BindingError> {
        Self::open_with_clock(path, Arc::new(SystemBindingClock))
    }

    /// Opens and verifies a durable binding database using an injected clock.
    pub fn open_with_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn BindingClock>,
    ) -> Result<Self, BindingError> {
        // URI filenames can select SQLite storage semantics outside the filesystem
        // path we subsequently harden; this adapter deliberately does not support them.
        if path.as_ref().to_string_lossy().starts_with("file:") {
            return Err(BindingError::StorageFailure);
        }
        let mut conn =
            open_with_pragmas(path.as_ref()).map_err(|_| BindingError::StorageFailure)?;
        apply_migrations_and_verify(&mut conn).map_err(|_| BindingError::StorageFailure)?;
        let path = (path.as_ref() != Path::new(":memory:")).then(|| path.as_ref().to_path_buf());
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
                clock,
                path,
            }),
        })
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, BindingError> {
        self.inner
            .conn
            .lock()
            .map_err(|_| BindingError::StorageFailure)
    }

    fn harden_after_write(&self) -> Result<(), BindingError> {
        if let Some(path) = &self.inner.path {
            harden_permissions(path).map_err(|_| BindingError::StorageFailure)?;
        }
        Ok(())
    }
}

impl SessionBindingStore for SqliteSessionBindingStore {
    fn ensure_pending(
        &self,
        key: &SessionBindingKey,
        context: &SessionBindingContext,
    ) -> Result<EnsurePendingResult, BindingError> {
        let snapshot = encode_context(context).map_err(|_| BindingError::SerializationFailed)?;
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::StorageFailure)?;
        if let Some(existing) = read_status(&tx, key)? {
            let exact = read_context(&tx, key)? == *context;
            if !exact {
                return Err(BindingError::Conflict(key.clone()));
            }
            return match existing.as_str() {
                "pending" => Ok(EnsurePendingResult::AlreadyPending),
                "committed" => Ok(EnsurePendingResult::AlreadyCommitted),
                _ => Err(BindingError::StorageFailure),
            };
        }
        validate_context_ids(context)?;
        let observed = self.inner.clock.now_millis()?.as_i64();
        let last: i64 = tx
            .query_row(
                "SELECT last_created_at FROM gocode_session_binding_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| BindingError::StorageFailure)?;
        let created_at = observed.max(last.checked_add(1).ok_or(BindingError::StorageFailure)?);
        if tx
            .execute(
                "UPDATE gocode_session_binding_state SET last_created_at=?1 WHERE singleton=1",
                params![created_at],
            )
            .map_err(|_| BindingError::StorageFailure)?
            != 1
        {
            return Err(BindingError::StorageFailure);
        }
        let result = tx.execute(
            "INSERT INTO session_bindings (session_id, profile_id, profile_revision, runtime_authority_id,
                conversation_id, workspace_id, command_id, idempotency_key, request_fingerprint,
                context_codec_version, context_snapshot, response_codec_version, response_snapshot, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, ?13, 'pending')",
            params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str(),
                context.conversation_id.as_bytes(), context.workspace_id.as_bytes(), context.command_id.as_bytes(),
                context.idempotency_key.as_str().as_bytes(), context.request_fingerprint.as_bytes(), i64::from(CODEC_VERSION), snapshot,
                i64::from(CODEC_VERSION), created_at],
        );
        match result {
            Ok(_) => {
                tx.commit().map_err(|_| BindingError::StorageFailure)?;
                self.harden_after_write()?;
                Ok(EnsurePendingResult::Created)
            }
            Err(error) if is_unique(&error) => Err(BindingError::Conflict(key.clone())),
            Err(_) => Err(BindingError::StorageFailure),
        }
    }

    fn commit(
        &self,
        key: &SessionBindingKey,
        expected_conversation_id: ConversationId,
        response: &OpenCodeSessionInfo,
    ) -> Result<(), BindingError> {
        let snapshot = encode_response(response).map_err(|_| BindingError::SerializationFailed)?;
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::StorageFailure)?;
        let row = read_row(&tx, key)?.ok_or_else(|| BindingError::NotFound(key.clone()))?;
        let context = decode_checked_context(&row, key)?;
        if context.conversation_id != expected_conversation_id {
            return Err(BindingError::Conflict(key.clone()));
        }
        match row.status.as_str() {
            "pending" => {
                if row.response.is_some() {
                    return Err(BindingError::StorageFailure);
                }
                let changes = tx.execute("UPDATE session_bindings SET status = 'committed', response_snapshot = ?1, response_codec_version = ?2
                    WHERE session_id = ?3 AND profile_id = ?4 AND profile_revision = ?5 AND runtime_authority_id = ?6 AND status = 'pending'",
                    params![snapshot, i64::from(CODEC_VERSION), key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()])
                    .map_err(|_| BindingError::StorageFailure)?;
                if changes != 1 {
                    return Err(BindingError::Conflict(key.clone()));
                }
                tx.commit().map_err(|_| BindingError::StorageFailure)?;
                self.harden_after_write()
            }
            "committed" => {
                let existing = row.response.ok_or(BindingError::StorageFailure)?;
                decode_response(&existing).map_err(|_| BindingError::SerializationFailed)?;
                if existing == snapshot {
                    Ok(())
                } else {
                    Err(BindingError::Conflict(key.clone()))
                }
            }
            _ => Err(BindingError::StorageFailure),
        }
    }

    fn lookup(
        &self,
        key: &SessionBindingKey,
    ) -> Result<Option<SessionBindingStatus>, BindingError> {
        let conn = self.connection()?;
        let row = read_row(&*conn, key)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let context = decode_checked_context(&row, key)?;
        match row.status.as_str() {
            "pending" if row.response.is_none() => {
                Ok(Some(SessionBindingStatus::Pending { context }))
            }
            "committed" => Ok(Some(SessionBindingStatus::Committed {
                context,
                response: decode_response(&row.response.ok_or(BindingError::StorageFailure)?)
                    .map_err(|_| BindingError::SerializationFailed)?,
            })),
            _ => Err(BindingError::StorageFailure),
        }
    }

    fn list_pending(
        &self,
        authority: &BindingRuntimeAuthorityId,
        limit: usize,
        after: Option<&(NonNegativeUnixMillis, SessionBindingKey)>,
    ) -> Result<Vec<(NonNegativeUnixMillis, SessionBindingKey)>, BindingError> {
        if limit == 0 || limit > MAX_RECOVERY_PENDING_LIMIT {
            return Err(BindingError::InvalidLimit {
                max: MAX_RECOVERY_PENDING_LIMIT,
                actual: limit,
            });
        }
        if let Some((_, key)) = after
            && key.runtime_authority_id != *authority
        {
            return Err(BindingError::Conflict(key.clone()));
        }
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::StorageFailure)?;
        if let Some((time, key)) = after {
            let cursor = tx.query_row("SELECT status, created_at FROM session_bindings WHERE session_id=?1 AND profile_id=?2 AND profile_revision=?3 AND runtime_authority_id=?4", params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))).optional().map_err(|_| BindingError::StorageFailure)?;
            if cursor != Some(("pending".to_owned(), time.as_i64())) {
                return Err(BindingError::Conflict(key.clone()));
            }
        }
        let mut statement = tx.prepare(
            "SELECT created_at, session_id, profile_id, profile_revision, runtime_authority_id
             FROM session_bindings WHERE runtime_authority_id = ?1 AND status = 'pending'
             AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND (session_id > ?3 OR
                (session_id = ?3 AND (profile_id > ?4 OR (profile_id = ?4 AND (profile_revision > ?5 OR
                (profile_revision = ?5 AND runtime_authority_id > ?6))))))))
             ORDER BY created_at, session_id, profile_id, profile_revision, runtime_authority_id LIMIT ?7"
        ).map_err(|_| BindingError::StorageFailure)?;
        let (timestamp, key) =
            after.map_or((None, None), |(time, key)| (Some(time.as_i64()), Some(key)));
        let rows = statement
            .query_map(
                params![
                    authority.as_str(),
                    timestamp,
                    key.map(|k| k.session_id.as_str()),
                    key.map(|k| k.profile_id.as_str()),
                    key.map(|k| i64::from(k.profile_revision)),
                    key.map(|k| k.runtime_authority_id.as_str()),
                    i64::try_from(limit).map_err(|_| BindingError::StorageFailure)?
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .map_err(|_| BindingError::StorageFailure)?;
        let mut output = Vec::new();
        for row in rows {
            let (created, session_id, profile_id, revision, runtime_authority_id) =
                row.map_err(|_| BindingError::StorageFailure)?;
            let time = NonNegativeUnixMillis::new(created).ok_or(BindingError::StorageFailure)?;
            let key = make_key(session_id, profile_id, revision, runtime_authority_id)?;
            output.push((time, key));
        }
        drop(statement);
        tx.commit().map_err(|_| BindingError::StorageFailure)?;
        Ok(output)
    }
}

trait Query {
    fn query_row<T, F>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        f: F,
    ) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>;
}
impl Query for Connection {
    fn query_row<T, F>(&self, sql: &str, params: impl rusqlite::Params, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        Connection::query_row(self, sql, params, f)
    }
}
impl Query for Transaction<'_> {
    fn query_row<T, F>(&self, sql: &str, params: impl rusqlite::Params, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        Connection::query_row(self, sql, params, f)
    }
}

struct RowData {
    status: String,
    conversation: Vec<u8>,
    workspace: Vec<u8>,
    command: Vec<u8>,
    idempotency: Vec<u8>,
    fingerprint: Vec<u8>,
    context_version: i64,
    context: Vec<u8>,
    response_version: i64,
    response: Option<Vec<u8>>,
}
fn read_status(
    tx: &Transaction<'_>,
    key: &SessionBindingKey,
) -> Result<Option<String>, BindingError> {
    tx.query_row("SELECT status FROM session_bindings WHERE session_id=?1 AND profile_id=?2 AND profile_revision=?3 AND runtime_authority_id=?4", params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()], |row| row.get(0)).optional().map_err(|_| BindingError::StorageFailure)
}
fn read_context(
    tx: &Transaction<'_>,
    key: &SessionBindingKey,
) -> Result<SessionBindingContext, BindingError> {
    let row = read_row(tx, key)?.ok_or_else(|| BindingError::NotFound(key.clone()))?;
    decode_checked_context(&row, key)
}
fn read_row(query: &impl Query, key: &SessionBindingKey) -> Result<Option<RowData>, BindingError> {
    query.query_row("SELECT status,conversation_id,workspace_id,command_id,idempotency_key,request_fingerprint,context_codec_version,context_snapshot,response_codec_version,response_snapshot FROM session_bindings WHERE session_id=?1 AND profile_id=?2 AND profile_revision=?3 AND runtime_authority_id=?4", params![key.session_id.as_str(), key.profile_id.as_str(), i64::from(key.profile_revision), key.runtime_authority_id.as_str()], |r| Ok(RowData { status:r.get(0)?, conversation:r.get(1)?, workspace:r.get(2)?, command:r.get(3)?, idempotency:r.get(4)?, fingerprint:r.get(5)?, context_version:r.get(6)?, context:r.get(7)?, response_version:r.get(8)?, response:r.get(9)? })).optional().map_err(|_| BindingError::StorageFailure)
}
fn decode_checked_context(
    row: &RowData,
    _key: &SessionBindingKey,
) -> Result<SessionBindingContext, BindingError> {
    if row.context_version != i64::from(CODEC_VERSION)
        || row.response_version != i64::from(CODEC_VERSION)
        || row.fingerprint.len() != 32
    {
        return Err(BindingError::SerializationFailed);
    }
    let context = decode_context(&row.context).map_err(|_| BindingError::SerializationFailed)?;
    if row.conversation != context.conversation_id.as_bytes()
        || row.workspace != context.workspace_id.as_bytes()
        || row.command != context.command_id.as_bytes()
        || row.idempotency != context.idempotency_key.as_str().as_bytes()
        || row.fingerprint != context.request_fingerprint.as_bytes()
    {
        return Err(BindingError::SerializationFailed);
    }
    Ok(context)
}
fn validate_context_ids(context: &SessionBindingContext) -> Result<(), BindingError> {
    gocode_domain::id::ConversationId::from_str(&context.conversation_id.to_string())
        .and_then(|id| {
            if id == context.conversation_id {
                Ok(id)
            } else {
                Err(gocode_domain::id::InvalidIdReason::InvalidUuidFormat)
            }
        })
        .map_err(|_| BindingError::SerializationFailed)?;
    gocode_domain::id::WorkspaceId::from_str(&context.workspace_id.to_string())
        .map_err(|_| BindingError::SerializationFailed)?;
    gocode_domain::id::CommandId::from_str(&context.command_id.to_string())
        .map_err(|_| BindingError::SerializationFailed)?;
    Ok(())
}
fn make_key(
    session_id: String,
    profile_id: String,
    revision: i64,
    authority: String,
) -> Result<SessionBindingKey, BindingError> {
    Ok(SessionBindingKey {
        session_id: gocode_opencode_compat::OpenCodeSessionId::new(session_id)
            .map_err(|_| BindingError::SerializationFailed)?,
        profile_id: gocode_opencode_compat::profile::ProfileId::new(profile_id)
            .map_err(|_| BindingError::SerializationFailed)?,
        profile_revision: u16::try_from(revision).map_err(|_| BindingError::SerializationFailed)?,
        runtime_authority_id: BindingRuntimeAuthorityId::new(authority)
            .map_err(|_| BindingError::SerializationFailed)?,
    })
}
fn is_unique(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::SqliteFailure(code, _) if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY || code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
}
