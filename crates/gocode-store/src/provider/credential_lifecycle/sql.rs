fn activate_lease(
    store: &SqliteProviderCredentialLifecycleStore,
    lease: CredentialLease,
    now: i64,
) -> Result<CredentialVersionRef, CredentialLifecycleError> {
    if now < 0 || lease.expires_at() <= now {
        return Err(CredentialLifecycleError::StaleLease);
    }
    let reference = lease.version_ref().clone();
    let mut connection = store.connection.lock().map_err(map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let row = load_row(&transaction, &reference)?.ok_or(CredentialLifecycleError::NotFound)?;
    validate_row_ref(&row, &reference)?;
    match row.state {
        CredentialVersionState::Prepared => {
            let high_water: i64 = transaction
                .query_row(
                    "SELECT COALESCE(MAX(MAX(revocation_fence,
                        COALESCE(lease_fencing_token, 0))), 0)
                     FROM provider_credential_versions WHERE provider_id=?1",
                    [reference.provider().as_str()],
                    |row| row.get(0),
                )
                .map_err(map_sql)?;
            if to_i64(lease.fencing_token())? <= high_water {
                return Err(CredentialLifecycleError::StaleLease);
            }
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
        CredentialVersionState::Retired | CredentialVersionState::GcClaimed
            if fence >= row.revocation_fence =>
        {
            transaction.commit().map_err(map_sql)
        }
        CredentialVersionState::Deleted if fence == row.revocation_fence => {
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
            "SELECT provider_id, credential_version, ref_digest
             FROM provider_credential_versions
             WHERE lifecycle_state='GC_CLAIMED' ORDER BY provider_id, credential_version",
        )
        .map_err(map_sql)?;
    let pairs = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    let claims = pairs
        .into_iter()
        .map(|(provider, version, stored_digest)| {
            let provider = gocode_provider::ProviderId::new(provider)
                .map_err(|_| CredentialLifecycleError::CorruptState)?;
            let version = u64::try_from(version)
                .map_err(|_| CredentialLifecycleError::CorruptState)?;
            let reference = CredentialVersionRef::new(provider, version)?;
            if stored_digest.as_slice() != reference.ref_digest() {
                return Err(CredentialLifecycleError::CorruptState);
            }
            Ok(store.authority.issue_gc(reference))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReconcileCredentialVersions::new(claims))
}
