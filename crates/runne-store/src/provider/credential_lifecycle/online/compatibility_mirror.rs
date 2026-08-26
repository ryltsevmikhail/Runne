use runne_provider::{CredentialLifecycleError, CredentialVersionRef, ProviderId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::rows::map_sql;

const MIRROR_LEASE_OWNER: [u8; 16] = *b"RUNNE_V24_MIRROR";

pub(super) fn activate(
    transaction: &Transaction<'_>,
    version: &CredentialVersionRef,
) -> Result<(), CredentialLifecycleError> {
    transaction
        .execute(
            "UPDATE provider_credential_versions
             SET lifecycle_state='RETIRED', revocation_fence=lease_fencing_token
             WHERE provider_id=?1 AND lifecycle_state='ACTIVE'
               AND credential_version!=?2",
            params![version.provider().as_str(), to_i64(version.version())?],
        )
        .map_err(map_sql)?;
    let token = next_token(transaction, version.provider())?;
    let state: Option<String> = transaction
        .query_row(
            "SELECT lifecycle_state FROM provider_credential_versions
             WHERE provider_id=?1 AND credential_version=?2",
            params![version.provider().as_str(), to_i64(version.version())?],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    match state.as_deref() {
        None => {
            transaction
                .execute(
                    "INSERT INTO provider_credential_versions
                     (provider_id, credential_version, ref_digest, lifecycle_state)
                     VALUES (?1, ?2, ?3, 'PREPARED')",
                    params![
                        version.provider().as_str(),
                        to_i64(version.version())?,
                        version.ref_digest().as_slice()
                    ],
                )
                .map_err(map_sql)?;
            activate_prepared(transaction, version, token)?;
        }
        Some("PREPARED") => activate_prepared(transaction, version, token)?,
        Some("ACTIVE") => return validate_active(transaction, version),
        Some(_) => return Err(CredentialLifecycleError::LifecycleClosed),
    };
    validate_active(transaction, version)
}

fn activate_prepared(
    transaction: &Transaction<'_>,
    version: &CredentialVersionRef,
    token: i64,
) -> Result<(), CredentialLifecycleError> {
    let changed = transaction
        .execute(
            "UPDATE provider_credential_versions
             SET lifecycle_state='ACTIVE', lease_owner=?1, lease_expires_at=?2,
                 lease_fencing_token=?3
             WHERE provider_id=?4 AND credential_version=?5
               AND ref_digest=?6 AND lifecycle_state='PREPARED'",
            params![
                MIRROR_LEASE_OWNER.as_slice(),
                i64::MAX,
                token,
                version.provider().as_str(),
                to_i64(version.version())?,
                version.ref_digest().as_slice()
            ],
        )
        .map_err(map_sql)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(CredentialLifecycleError::Conflict)
    }
}

pub(super) fn delete(
    transaction: &Transaction<'_>,
    version: &CredentialVersionRef,
) -> Result<(), CredentialLifecycleError> {
    let tombstone = crate::provider::credential_lifecycle::tombstone_digest(version);
    transaction
        .execute(
            "UPDATE provider_credential_versions
             SET lifecycle_state='RETIRED', revocation_fence=lease_fencing_token
             WHERE provider_id=?1 AND credential_version=?2 AND ref_digest=?3
               AND lifecycle_state='ACTIVE'",
            params![
                version.provider().as_str(),
                to_i64(version.version())?,
                version.ref_digest().as_slice()
            ],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_versions SET lifecycle_state='GC_CLAIMED'
             WHERE provider_id=?1 AND credential_version=?2 AND ref_digest=?3
               AND lifecycle_state='RETIRED'",
            params![
                version.provider().as_str(),
                to_i64(version.version())?,
                version.ref_digest().as_slice()
            ],
        )
        .map_err(map_sql)?;
    let changed = transaction
        .execute(
            "UPDATE provider_credential_versions
             SET lifecycle_state='DELETED', tombstone_digest=?1
             WHERE provider_id=?2 AND credential_version=?3 AND ref_digest=?4
               AND lifecycle_state='GC_CLAIMED'",
            params![
                tombstone.as_slice(),
                version.provider().as_str(),
                to_i64(version.version())?,
                version.ref_digest().as_slice()
            ],
        )
        .map_err(map_sql)?;
    if changed == 1 || deleted_with(transaction, version, &tombstone)? {
        Ok(())
    } else {
        Err(CredentialLifecycleError::CorruptState)
    }
}

pub(super) fn retire_active(
    transaction: &Transaction<'_>,
    provider: &ProviderId,
) -> Result<(), CredentialLifecycleError> {
    transaction
        .execute(
            "UPDATE provider_credential_versions
             SET lifecycle_state='RETIRED', revocation_fence=lease_fencing_token
             WHERE provider_id=?1 AND lifecycle_state='ACTIVE'",
            [provider.as_str()],
        )
        .map_err(map_sql)?;
    Ok(())
}

fn next_token(
    transaction: &Transaction<'_>,
    provider: &ProviderId,
) -> Result<i64, CredentialLifecycleError> {
    let high_water: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(MAX(revocation_fence,
                    COALESCE(lease_fencing_token, 0))), 0)
             FROM provider_credential_versions WHERE provider_id=?1",
            [provider.as_str()],
            |row| row.get(0),
        )
        .map_err(map_sql)?;
    high_water
        .checked_add(1)
        .ok_or(CredentialLifecycleError::CorruptState)
}

fn validate_active(
    transaction: &Transaction<'_>,
    version: &CredentialVersionRef,
) -> Result<(), CredentialLifecycleError> {
    let valid: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM provider_credential_versions
             WHERE provider_id=?1 AND credential_version=?2 AND ref_digest=?3
               AND lifecycle_state='ACTIVE' AND lease_owner=?4
               AND lease_expires_at=?5 AND lease_fencing_token>0
               AND revocation_fence<lease_fencing_token",
            params![
                version.provider().as_str(),
                to_i64(version.version())?,
                version.ref_digest().as_slice(),
                MIRROR_LEASE_OWNER.as_slice(),
                i64::MAX
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    valid
        .map(|_| ())
        .ok_or(CredentialLifecycleError::CorruptState)
}

fn deleted_with(
    transaction: &Transaction<'_>,
    version: &CredentialVersionRef,
    tombstone: &[u8; 32],
) -> Result<bool, CredentialLifecycleError> {
    transaction
        .query_row(
            "SELECT 1 FROM provider_credential_versions
             WHERE provider_id=?1 AND credential_version=?2 AND ref_digest=?3
               AND lifecycle_state='DELETED' AND tombstone_digest=?4",
            params![
                version.provider().as_str(),
                to_i64(version.version())?,
                version.ref_digest().as_slice(),
                tombstone.as_slice()
            ],
            |_| Ok(true),
        )
        .optional()
        .map(|value| value.unwrap_or(false))
        .map_err(map_sql)
}

fn to_i64(value: u64) -> Result<i64, CredentialLifecycleError> {
    i64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider::ProviderId;
    use rusqlite::{Connection, TransactionBehavior};

    #[test]
    fn compatibility_token_is_monotonic_and_independent_of_v24_fences() {
        let mut connection = Connection::open_in_memory().unwrap();
        crate::schema::apply_migrations(&connection).unwrap();
        let provider = ProviderId::new("openai").unwrap();
        let first = CredentialVersionRef::new(provider.clone(), 1).unwrap();
        let second = CredentialVersionRef::new(provider, 2).unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();

        activate(&transaction, &first).unwrap();
        activate(&transaction, &second).unwrap();

        let rows: Vec<(i64, String, i64)> = transaction
            .prepare(
                "SELECT credential_version, lifecycle_state, lease_fencing_token
                 FROM provider_credential_versions ORDER BY credential_version",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(1, "RETIRED".into(), 1), (2, "ACTIVE".into(), 2)]
        );
    }
}
