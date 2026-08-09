use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use gocode_provider::{
    CredentialAuthorityPair, CredentialLease, CredentialLifecycleAuthority,
    CredentialLifecycleError, CredentialNativeCreateClaim, CredentialNativeCreateValidator,
    CredentialProvisionSource, CredentialVersionRef, CredentialVersionState,
    NativeCredentialDeletionProof, PrepareCredentialVersion, ProviderCredentialVersionStore,
    ReconcileCredentialVersions, RevokeCredentialVersion,
};
use rusqlite::{TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, open_managed_connection,
    publication_from_managed, readiness_from_managed,
};

use super::CredentialDispatchBinding;

include!("credential_lifecycle/row.rs");
include!("credential_lifecycle/clock.rs");
include!("credential_lifecycle/sql.rs");
include!("credential_lifecycle/dispatch_ops.rs");
include!("credential_lifecycle/diagnostics.rs");
include!("credential_lifecycle/provision.rs");

#[cfg(test)]
mod tests;

const TOMBSTONE_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_TOMBSTONE_V1\0";

/// SQLite authority for credential versions, leases, fences, and tombstones.
pub struct SqliteProviderCredentialLifecycleStore {
    connection: Arc<Mutex<ManagedConnection>>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    authority: CredentialLifecycleAuthority,
}

impl SqliteProviderCredentialLifecycleStore {
    /// Opens through the managed profile and validates the exact released schema.
    pub fn open(path: &Path) -> Result<Self, CredentialLifecycleError> {
        Self::open_with_now(path, Arc::new(unix_timestamp))
    }

    fn open_with_now(
        path: &Path,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, CredentialLifecycleError> {
        let (authority, _) = CredentialAuthorityPair::new().split();
        Self::open_with_authority_and_now(path, authority, now)
    }

    fn open_with_authority_and_now(
        path: &Path,
        authority: CredentialLifecycleAuthority,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, CredentialLifecycleError> {
        let connection = open_managed_connection(path, ConnectionMode::Writer).map_err(map_sql)?;
        Self::open_with_connection_authority_and_now(connection, authority, now)
    }

    /// Opens the lifecycle store in one process-local native authority domain.
    pub fn open_with_authority(
        path: &Path,
        authority: CredentialLifecycleAuthority,
    ) -> Result<Self, CredentialLifecycleError> {
        Self::open_with_authority_and_now(path, authority, Arc::new(unix_timestamp))
    }

    /// Adopts a factory-issued managed writable connection.
    pub fn open_with_connection(
        connection: ManagedConnection,
    ) -> Result<Self, CredentialLifecycleError> {
        let (authority, _) = CredentialAuthorityPair::new().split();
        Self::open_with_connection_authority_and_now(
            connection,
            authority,
            Arc::new(unix_timestamp),
        )
    }

    /// Adopts a validated writable connection in one native authority domain.
    pub fn open_with_connection_and_authority(
        connection: ManagedConnection,
        authority: CredentialLifecycleAuthority,
    ) -> Result<Self, CredentialLifecycleError> {
        Self::open_with_connection_authority_and_now(
            connection,
            authority,
            Arc::new(unix_timestamp),
        )
    }

    fn open_with_connection_authority_and_now(
        connection: ManagedConnection,
        authority: CredentialLifecycleAuthority,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, CredentialLifecycleError> {
        apply_migrations(&connection).map_err(map_sql)?;
        readiness_from_managed(&connection).map_err(map_sql)?;
        publication_from_managed(&connection).map_err(map_sql)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            now,
            authority,
        })
    }

    /// Opens with a fixed clock for deterministic lifecycle verification.
    #[doc(hidden)]
    pub fn open_at(path: &Path, now: i64) -> Result<Self, CredentialLifecycleError> {
        Self::open_with_now(path, Arc::new(move || now))
    }

    /// Opens with paired native authority and a fixed verification clock.
    #[doc(hidden)]
    pub fn open_at_with_authority(
        path: &Path,
        authority: CredentialLifecycleAuthority,
        now: i64,
    ) -> Result<Self, CredentialLifecycleError> {
        Self::open_with_authority_and_now(path, authority, Arc::new(move || now))
    }

    /// Adopts a validated test connection with a fixed clock.
    #[doc(hidden)]
    pub fn open_connection_at(
        connection: ManagedConnection,
        now: i64,
    ) -> Result<Self, CredentialLifecycleError> {
        let (authority, _) = CredentialAuthorityPair::new().split();
        Self::open_with_connection_authority_and_now(connection, authority, Arc::new(move || now))
    }
}

impl ProviderCredentialVersionStore for SqliteProviderCredentialLifecycleStore {
    fn create_prepared(
        &self,
        input: PrepareCredentialVersion,
    ) -> Result<CredentialVersionRef, CredentialLifecycleError> {
        let reference = input.version_ref();
        let mut connection = self.connection.lock().map_err(map_lock)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if let Some(row) = load_row(&transaction, reference)? {
            validate_row_ref(&row, reference)?;
            return if row.state == CredentialVersionState::Prepared {
                transaction.commit().map_err(map_sql)?;
                Ok(reference.clone())
            } else {
                Err(CredentialLifecycleError::Conflict)
            };
        }
        transaction
            .execute(
                "INSERT INTO provider_credential_versions
                 (provider_id, credential_version, ref_digest, lifecycle_state)
                 VALUES (?1, ?2, ?3, 'PREPARED')",
                params![
                    reference.provider().as_str(),
                    to_i64(reference.version())?,
                    reference.ref_digest().as_slice()
                ],
            )
            .map_err(map_sql)?;
        transaction.commit().map_err(map_sql)?;
        Ok(reference.clone())
    }

    fn activate(
        &self,
        lease: CredentialLease,
    ) -> Result<CredentialVersionRef, CredentialLifecycleError> {
        activate_lease(self, lease)
    }

    fn revoke_and_fence(
        &self,
        input: RevokeCredentialVersion,
    ) -> Result<(), CredentialLifecycleError> {
        revoke_lease(self, input)
    }

    fn reconcile(&self, now: i64) -> Result<ReconcileCredentialVersions, CredentialLifecycleError> {
        reconcile_versions(self, now)
    }
}

fn tombstone_digest(reference: &CredentialVersionRef) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOMBSTONE_DOMAIN);
    hasher.update(reference.ref_digest());
    hasher.finalize().into()
}

fn map_sql(_error: rusqlite::Error) -> CredentialLifecycleError {
    CredentialLifecycleError::StoreUnavailable
}

fn map_lock<T>(_error: std::sync::PoisonError<T>) -> CredentialLifecycleError {
    CredentialLifecycleError::StoreUnavailable
}

fn to_i64(value: u64) -> Result<i64, CredentialLifecycleError> {
    i64::try_from(value).map_err(|_| CredentialLifecycleError::InvalidInput)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(-1, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}
