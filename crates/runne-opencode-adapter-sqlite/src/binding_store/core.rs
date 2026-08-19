
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_api::{NonNegativeUnixMillis, OpenCodeSessionInfo};
use runne_domain::id::ConversationId;
use runne_opencode_compat::{
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
