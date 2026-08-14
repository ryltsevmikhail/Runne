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
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql)?;
    raw.map(decode_row).transpose()
}

fn load_active_row(
    connection: &Connection,
    provider: &gocode_provider::ProviderId,
) -> Result<Option<(CredentialRow, CredentialVersionRef)>, CredentialLifecycleError> {
    let raw: Option<RawCredentialRow> = connection
        .query_row(
            "SELECT provider_id, credential_version, ref_digest, lifecycle_state,
                    lease_owner, lease_expires_at, lease_fencing_token,
                    revocation_fence, tombstone_digest
             FROM provider_credential_versions
             WHERE provider_id=?1 AND lifecycle_state='ACTIVE'",
            [provider.as_str()],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql)?;
    raw.map(|raw| {
        let row = decode_row(raw)?;
        let version =
            u64::try_from(row.version).map_err(|_| CredentialLifecycleError::CorruptState)?;
        Ok((row, CredentialVersionRef::new(provider.clone(), version)?))
    })
    .transpose()
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
