//! Durable SQLite sidecar persistence for the T1 project trust state.
//!
//! The trust state lives in its own sidecar database next to the canonical
//! store (the same pattern as the scanner-recovery sidecar), so the shared
//! migration chain stays untouched. Every sidecar owns an unpredictable
//! instance epoch drawn once from the OS CSPRNG (never wall-clock time) and
//! stored in the identity row; revisions are only meaningful inside that
//! epoch, which closes delete/recreate ABA replay (F1). Reopening verifies
//! the identity row (kind, version, epoch presence, runtime authority) and
//! fails closed on any mismatch or corruption.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand::RngCore;
use runne_application::project_trust::{
    ProjectTrustEffectLease, ProjectTrustRecord, TrustPersistenceError,
};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::schema::{self, ConnectionMode, ManagedConnection};

pub(crate) const PROJECT_TRUST_SCHEMA_KIND: &str = "runne.project-trust";
pub(crate) const PROJECT_TRUST_SCHEMA_VERSION: i64 = 2;
pub(crate) const PROJECT_TRUST_SIDECAR_VERSION: i64 = 2;

pub(crate) const PROJECT_TRUST_IDENTITY_SQL: &str = "CREATE TABLE project_trust_schema (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    schema_kind TEXT NOT NULL CHECK(schema_kind = 'runne.project-trust'),
    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
    instance_epoch INTEGER NOT NULL CHECK(instance_epoch > 0),
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16)
)";

pub(crate) const PROJECT_TRUST_TRUST_SQL: &str = "CREATE TABLE project_trust (
    project_id BLOB PRIMARY KEY CHECK(length(project_id) = 16),
    status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 3),
    managed_deny_mask INTEGER NOT NULL CHECK(managed_deny_mask >= 0),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    updated_at INTEGER NOT NULL
)";

/// Fail-closed store errors.
#[derive(Debug)]
pub enum ProjectTrustStoreError {
    /// The sidecar could not be opened or verified.
    Unavailable,
}

/// Managed SQLite sidecar store for project trust state.
#[derive(Clone)]
pub struct ProjectTrustStore {
    connection: Arc<Mutex<ManagedConnection>>,
    instance_epoch: u64,
    sidecar_path: PathBuf,
    authority_id: [u8; 16],
}

impl ProjectTrustStore {
    /// Opens (creating if needed) the `<canonical>.project-trust` sidecar.
    ///
    /// F4: `canonical_path` must be absolute; relative paths fail closed.
    pub fn open(
        canonical_path: &Path,
        authority_id: [u8; 16],
    ) -> Result<Self, ProjectTrustStoreError> {
        if !canonical_path.is_absolute() {
            return Err(ProjectTrustStoreError::Unavailable);
        }
        let mut sidecar_name = canonical_path.as_os_str().to_owned();
        sidecar_name.push(".project-trust");
        let sidecar_path = PathBuf::from(&sidecar_name);
        if sidecar_path.exists() {
            Self::reopen(&sidecar_path, authority_id)
        } else {
            Self::create(&sidecar_path, authority_id)
        }
    }

    fn fresh_epoch() -> u64 {
        // OS CSPRNG, not wall-clock: unpredictable per instance (F1). A draw
        // that masks to zero is redrawn, so a durable zero epoch is
        // impossible; the durable range is the positive 63-bit integers.
        loop {
            if let Some(epoch) = masked_epoch(rand::rngs::OsRng.next_u64()) {
                return epoch;
            }
        }
    }

    fn create(path: &Path, authority_id: [u8; 16]) -> Result<Self, ProjectTrustStoreError> {
        let instance_epoch = Self::fresh_epoch();
        let mut connection = schema::open_managed_connection(path, ConnectionMode::Writer)
            .map_err(|_| ProjectTrustStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProjectTrustStoreError::Unavailable)?;
        transaction
            .execute_batch(PROJECT_TRUST_IDENTITY_SQL)
            .and_then(|_| transaction.execute_batch(PROJECT_TRUST_TRUST_SQL))
            .map_err(|_| ProjectTrustStoreError::Unavailable)?;
        transaction
            .pragma_update(None, "user_version", PROJECT_TRUST_SIDECAR_VERSION)
            .map_err(|_| ProjectTrustStoreError::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO project_trust_schema
                 (id, schema_kind, schema_version, instance_epoch, authority_id)
                 VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    PROJECT_TRUST_SCHEMA_KIND,
                    PROJECT_TRUST_SCHEMA_VERSION,
                    instance_epoch as i64,
                    authority_id.as_slice()
                ],
            )
            .map_err(|_| ProjectTrustStoreError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| ProjectTrustStoreError::Unavailable)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            instance_epoch,
            sidecar_path: path.to_path_buf(),
            authority_id,
        })
    }

    fn reopen(path: &Path, authority_id: [u8; 16]) -> Result<Self, ProjectTrustStoreError> {
        let (connection, instance_epoch) =
            schema::reopen_managed_project_trust_sidecar(path, authority_id)
                .map_err(|_| ProjectTrustStoreError::Unavailable)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            instance_epoch,
            sidecar_path: path.to_path_buf(),
            authority_id,
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, TrustPersistenceError>,
    ) -> Result<T, TrustPersistenceError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        connection
            .verify_retained_identity()
            .map_err(|_| TrustPersistenceError::Unavailable)?;
        operation(&connection)
    }
}

struct StoreProjectTrustEffectLease {
    connection: Option<ManagedConnection>,
    record: ProjectTrustRecord,
}

impl ProjectTrustEffectLease for StoreProjectTrustEffectLease {
    fn record(&self) -> ProjectTrustRecord {
        self.record
    }
}

impl Drop for StoreProjectTrustEffectLease {
    fn drop(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            let _ = connection.with_connection_mut(|raw| raw.execute_batch("ROLLBACK"));
        }
    }
}

/// Masks one CSPRNG draw to the positive 63-bit epoch range.
///
/// Returns `None` when the masked draw is zero (or becomes zero through
/// masking), which makes the caller draw again; zero epochs can therefore
/// never become durable.
fn masked_epoch(raw: u64) -> Option<u64> {
    let candidate = raw & 0x7fff_ffff_ffff_ffff;
    (candidate != 0).then_some(candidate)
}

mod control;
mod persistence;

#[cfg(all(test, unix))]
mod control_tests;
#[cfg(all(test, unix))]
mod effect_lease_tests;

#[cfg(test)]
mod tests {
    use super::masked_epoch;

    #[test]
    fn zero_draws_never_become_durable_epochs() {
        assert_eq!(masked_epoch(0), None, "zero must be redrawn");
    }

    #[test]
    fn high_bit_only_draws_mask_to_zero_and_redraw() {
        // 1 << 63 has only the sign bit set: masking yields zero → redraw.
        assert_eq!(masked_epoch(1 << 63), None);
    }

    #[test]
    fn full_range_draw_maps_to_positive_63_bit_epoch() {
        // u64::MAX masks to the largest positive 63-bit integer; the durable
        // epoch space is exactly 1..=2^63-1, never a negative i64.
        assert_eq!(masked_epoch(u64::MAX), Some(0x7fff_ffff_ffff_ffff));
        assert_eq!(masked_epoch(1), Some(1));
    }
}
