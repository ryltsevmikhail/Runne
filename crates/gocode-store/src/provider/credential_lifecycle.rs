use std::{path::Path, sync::Mutex};

use gocode_provider::{
    CredentialLease, CredentialLifecycleError, CredentialVersionRef, CredentialVersionState,
    PrepareCredentialVersion, ProviderCredentialVersionStore, ReconcileCredentialVersions,
    RevokeCredentialVersion,
};
use rusqlite::{TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, open_managed_connection,
    publication_from_managed, readiness_from_managed,
};

use super::CredentialDispatchBinding;

include!("credential_lifecycle/sql.rs");

const TOMBSTONE_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_TOMBSTONE_V1\0";

/// SQLite authority for credential versions, leases, fences, and tombstones.
pub struct SqliteProviderCredentialLifecycleStore {
    connection: Mutex<ManagedConnection>,
}

impl SqliteProviderCredentialLifecycleStore {
    /// Opens through the managed profile and validates the exact released schema.
    pub fn open(path: &Path) -> Result<Self, CredentialLifecycleError> {
        let connection = open_managed_connection(path, ConnectionMode::Writer).map_err(map_sql)?;
        Self::open_with_connection(connection)
    }

    /// Adopts a factory-issued managed writable connection.
    pub fn open_with_connection(
        connection: ManagedConnection,
    ) -> Result<Self, CredentialLifecycleError> {
        apply_migrations(&connection).map_err(map_sql)?;
        readiness_from_managed(&connection).map_err(map_sql)?;
        publication_from_managed(&connection).map_err(map_sql)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Produces a dispatch binding only while the exact lease remains active.
    pub fn authorize_dispatch(
        &self,
        lease: &CredentialLease,
        now: i64,
    ) -> Result<CredentialDispatchBinding, CredentialLifecycleError> {
        if now < 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        let connection = self.connection.lock().map_err(map_lock)?;
        let row = load_row(&connection, lease.version_ref())?
            .ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, lease.version_ref())?;
        if row.state != CredentialVersionState::Active
            || row.lease_owner.as_deref() != Some(lease.owner().as_slice())
            || row.lease_expires_at != Some(lease.expires_at())
            || row.lease_fencing_token != Some(to_i64(lease.fencing_token())?)
            || lease.expires_at() <= now
            || row.revocation_fence >= to_i64(lease.fencing_token())?
        {
            return Err(CredentialLifecycleError::StaleLease);
        }
        Ok(CredentialDispatchBinding::from_authoritative_lease(
            lease.clone(),
        ))
    }

    /// Revalidates a previously issued binding immediately before effect.
    pub fn validate_dispatch(
        &self,
        binding: &CredentialDispatchBinding,
        now: i64,
    ) -> Result<(), CredentialLifecycleError> {
        self.authorize_dispatch(binding.lease(), now).map(|_| ())
    }

    /// Marks a tombstone only after the caller completed native deletion.
    pub fn complete_native_delete(
        &self,
        reference: CredentialVersionRef,
    ) -> Result<(), CredentialLifecycleError> {
        let digest = tombstone_digest(&reference);
        let mut connection = self.connection.lock().map_err(map_lock)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let row = load_row(&transaction, &reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, &reference)?;
        match row.state {
            CredentialVersionState::GcClaimed => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_credential_versions
                         SET lifecycle_state='DELETED', tombstone_digest=?1
                         WHERE provider_id=?2 AND credential_version=?3
                           AND lifecycle_state='GC_CLAIMED'",
                        params![
                            digest.as_slice(),
                            reference.provider().as_str(),
                            to_i64(reference.version())?
                        ],
                    )
                    .map_err(map_sql)?;
                if changed != 1 {
                    return Err(CredentialLifecycleError::Conflict);
                }
                transaction.commit().map_err(map_sql)
            }
            CredentialVersionState::Deleted if row.tombstone_digest.as_deref() == Some(&digest) => {
                transaction.commit().map_err(map_sql)
            }
            CredentialVersionState::Deleted => Err(CredentialLifecycleError::CorruptState),
            _ => Err(CredentialLifecycleError::LifecycleClosed),
        }
    }

    /// Reads the durable lifecycle state for diagnostics and reconciliation.
    pub fn version_state(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<CredentialVersionState, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let row = load_row(&connection, reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, reference)?;
        Ok(row.state)
    }

    /// Reads a non-secret tombstone digest, if native deletion completed.
    pub fn tombstone_digest(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<Option<[u8; 32]>, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let row = load_row(&connection, reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, reference)?;
        row.tombstone_digest
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| CredentialLifecycleError::CorruptState)
            })
            .transpose()
    }

    /// Reads the current revocation fence without credential material.
    pub fn revocation_fence(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<u64, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let row = load_row(&connection, reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, reference)?;
        u64::try_from(row.revocation_fence).map_err(|_| CredentialLifecycleError::CorruptState)
    }

    /// Counts exact active winners for one provider identity.
    pub fn active_version_count(&self, provider: &str) -> Result<u64, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM provider_credential_versions
                 WHERE provider_id=?1 AND lifecycle_state='ACTIVE'",
                [provider],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        u64::try_from(count).map_err(|_| CredentialLifecycleError::CorruptState)
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
