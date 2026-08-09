use rusqlite::{Connection, OptionalExtension};

struct CredentialRow {
    provider_id: String,
    version: i64,
    ref_digest: Vec<u8>,
    state: CredentialVersionState,
    lease_owner: Option<Vec<u8>>,
    lease_expires_at: Option<i64>,
    lease_fencing_token: Option<i64>,
    revocation_fence: i64,
    tombstone_digest: Option<Vec<u8>>,
}

type RawCredentialRow = (
    String,
    i64,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    i64,
    Option<Vec<u8>>,
);

fn load_row(
    connection: &Connection,
    reference: &CredentialVersionRef,
) -> Result<Option<CredentialRow>, CredentialLifecycleError> {
    let raw: Option<RawCredentialRow> = connection
        .query_row(
            "SELECT provider_id, credential_version, ref_digest, lifecycle_state,
                    lease_owner, lease_expires_at, lease_fencing_token,
                    revocation_fence, tombstone_digest
             FROM provider_credential_versions
             WHERE provider_id=?1 AND credential_version=?2",
            params![reference.provider().as_str(), to_i64(reference.version())?],
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
                ))
            },
        )
        .optional()
        .map_err(map_sql)?;
    raw.map(decode_row).transpose()
}

fn decode_row(raw: RawCredentialRow) -> Result<CredentialRow, CredentialLifecycleError> {
    let state = match raw.3.as_str() {
        "PREPARED" => CredentialVersionState::Prepared,
        "ACTIVE" => CredentialVersionState::Active,
        "RETIRED" => CredentialVersionState::Retired,
        "GC_CLAIMED" => CredentialVersionState::GcClaimed,
        "DELETED" => CredentialVersionState::Deleted,
        _ => return Err(CredentialLifecycleError::CorruptState),
    };
    Ok(CredentialRow {
        provider_id: raw.0,
        version: raw.1,
        ref_digest: raw.2,
        state,
        lease_owner: raw.4,
        lease_expires_at: raw.5,
        lease_fencing_token: raw.6,
        revocation_fence: raw.7,
        tombstone_digest: raw.8,
    })
}

fn validate_row_ref(
    row: &CredentialRow,
    reference: &CredentialVersionRef,
) -> Result<(), CredentialLifecycleError> {
    if row.provider_id == reference.provider().as_str()
        && row.version == to_i64(reference.version())?
        && row.ref_digest.as_slice() == reference.ref_digest()
    {
        Ok(())
    } else {
        Err(CredentialLifecycleError::CorruptState)
    }
}

fn activate_lease(
    store: &SqliteProviderCredentialLifecycleStore,
    lease: CredentialLease,
) -> Result<CredentialVersionRef, CredentialLifecycleError> {
    let reference = lease.version_ref().clone();
    let mut connection = store.connection.lock().map_err(map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let row = load_row(&transaction, &reference)?.ok_or(CredentialLifecycleError::NotFound)?;
    validate_row_ref(&row, &reference)?;
    match row.state {
        CredentialVersionState::Prepared => {
            let changed = transaction
                .execute(
                    "UPDATE provider_credential_versions
                     SET lifecycle_state='ACTIVE', lease_owner=?1, lease_expires_at=?2,
                         lease_fencing_token=?3
                     WHERE provider_id=?4 AND credential_version=?5
                       AND lifecycle_state='PREPARED'
                       AND NOT EXISTS (
                           SELECT 1 FROM provider_credential_versions
                           WHERE provider_id=?4 AND lifecycle_state='ACTIVE'
                       )",
                    params![
                        lease.owner().as_slice(),
                        lease.expires_at(),
                        to_i64(lease.fencing_token())?,
                        reference.provider().as_str(),
                        to_i64(reference.version())?
                    ],
                )
                .map_err(map_sql)?;
            if changed != 1 {
                return Err(CredentialLifecycleError::Conflict);
            }
            transaction.commit().map_err(map_sql)?;
            Ok(reference)
        }
        CredentialVersionState::Active if row_matches_lease(&row, &lease)? => {
            transaction.commit().map_err(map_sql)?;
            Ok(reference)
        }
        CredentialVersionState::Active => Err(CredentialLifecycleError::Conflict),
        _ => Err(CredentialLifecycleError::LifecycleClosed),
    }
}

fn row_matches_lease(
    row: &CredentialRow,
    lease: &CredentialLease,
) -> Result<bool, CredentialLifecycleError> {
    Ok(row.lease_owner.as_deref() == Some(lease.owner().as_slice())
        && row.lease_expires_at == Some(lease.expires_at())
        && row.lease_fencing_token == Some(to_i64(lease.fencing_token())?))
}

fn revoke_lease(
    store: &SqliteProviderCredentialLifecycleStore,
    input: RevokeCredentialVersion,
) -> Result<(), CredentialLifecycleError> {
    let reference = input.version_ref();
    let fence = to_i64(input.revocation_fence())?;
    let mut connection = store.connection.lock().map_err(map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let row = load_row(&transaction, reference)?.ok_or(CredentialLifecycleError::NotFound)?;
    validate_row_ref(&row, reference)?;
    if row.state == CredentialVersionState::Active {
        if row.lease_fencing_token.is_none_or(|active| fence < active) {
            return Err(CredentialLifecycleError::StaleLease);
        }
        let changed = transaction
            .execute(
                "UPDATE provider_credential_versions
                 SET lifecycle_state='RETIRED', revocation_fence=?1
                 WHERE provider_id=?2 AND credential_version=?3
                   AND lifecycle_state='ACTIVE' AND lease_fencing_token<=?1",
                params![fence, reference.provider().as_str(), to_i64(reference.version())?],
            )
            .map_err(map_sql)?;
        if changed != 1 {
            return Err(CredentialLifecycleError::Conflict);
        }
        return transaction.commit().map_err(map_sql);
    }
    match row.state {
        CredentialVersionState::Retired
        | CredentialVersionState::GcClaimed
        | CredentialVersionState::Deleted
            if fence >= row.revocation_fence =>
        {
            transaction.commit().map_err(map_sql)
        }
        CredentialVersionState::Prepared => Err(CredentialLifecycleError::Conflict),
        _ => Err(CredentialLifecycleError::StaleLease),
    }
}

fn reconcile_versions(
    store: &SqliteProviderCredentialLifecycleStore,
    now: i64,
) -> Result<ReconcileCredentialVersions, CredentialLifecycleError> {
    if now < 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let mut connection = store.connection.lock().map_err(map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_versions
             SET lifecycle_state='RETIRED', revocation_fence=lease_fencing_token
             WHERE lifecycle_state='ACTIVE' AND lease_expires_at<=?1",
            [now],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_versions SET lifecycle_state='GC_CLAIMED'
             WHERE lifecycle_state='RETIRED'
               AND (lease_expires_at<=?1 OR revocation_fence>=lease_fencing_token)",
            [now],
        )
        .map_err(map_sql)?;
    transaction.commit().map_err(map_sql)?;
    drop(connection);

    let connection = store.connection.lock().map_err(map_lock)?;
    let mut statement = connection
        .prepare(
            "SELECT provider_id, credential_version FROM provider_credential_versions
             WHERE lifecycle_state='GC_CLAIMED' ORDER BY provider_id, credential_version",
        )
        .map_err(map_sql)?;
    let pairs = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    let references = pairs
        .into_iter()
        .map(|(provider, version)| {
            let provider = gocode_provider::ProviderId::new(provider)
                .map_err(|_| CredentialLifecycleError::CorruptState)?;
            let version = u64::try_from(version)
                .map_err(|_| CredentialLifecycleError::CorruptState)?;
            CredentialVersionRef::new(provider, version)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReconcileCredentialVersions::new(references))
}
