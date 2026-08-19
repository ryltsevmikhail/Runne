fn adopt_or_create_prepared(
    transaction: &rusqlite::Transaction<'_>,
    provider: &runne_provider::ProviderId,
) -> Result<CredentialVersionRef, CredentialLifecycleError> {
    let mut statement = transaction
        .prepare(
            "SELECT credential_version, ref_digest FROM provider_credential_versions
             WHERE provider_id=?1 AND lifecycle_state='PREPARED'
             ORDER BY credential_version",
        )
        .map_err(map_sql)?;
    let prepared = statement
        .query_map([provider.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    if prepared.len() > 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    if let Some((version, digest)) = prepared.into_iter().next() {
        let version =
            u64::try_from(version).map_err(|_| CredentialLifecycleError::CorruptState)?;
        let reference = CredentialVersionRef::new(provider.clone(), version)?;
        if digest.as_slice() != reference.ref_digest() {
            return Err(CredentialLifecycleError::CorruptState);
        }
        return Ok(reference);
    }
    let high_water: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(credential_version), 0)
             FROM provider_credential_versions WHERE provider_id=?1",
            [provider.as_str()],
            |row| row.get(0),
        )
        .map_err(map_sql)?;
    let version = u64::try_from(high_water)
        .map_err(|_| CredentialLifecycleError::CorruptState)?
        .checked_add(1)
        .ok_or(CredentialLifecycleError::InvalidInput)?;
    let reference = CredentialVersionRef::new(provider.clone(), version)?;
    transaction
        .execute(
            "INSERT INTO provider_credential_versions
             (provider_id, credential_version, ref_digest, lifecycle_state)
             VALUES (?1, ?2, ?3, 'PREPARED')",
            params![
                provider.as_str(),
                to_i64(version)?,
                reference.ref_digest().as_slice()
            ],
        )
        .map_err(map_sql)?;
    Ok(reference)
}
