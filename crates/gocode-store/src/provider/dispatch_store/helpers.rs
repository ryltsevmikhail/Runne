fn validate_claim(claim: &ProviderDispatchClaim) -> Result<(), ProviderStoreError> {
    if claim.fencing_token == 0 {
        return Err(ProviderStoreError::StaleFencingToken);
    }
    if claim.provider_idempotency_key.is_empty()
        || claim.provider_idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || claim
            .provider_idempotency_key
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderStoreError::InvalidIdempotencyKey);
    }
    Ok(())
}

fn prepared_record_digest(record: &PreparedProviderRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_DOMAIN);
    hasher.update(record.call_id.as_bytes());
    hasher.update(record.prepared_digest);
    hasher.update(record.render_digest);
    hasher.update(record.profile_digest);
    hasher.finalize().into()
}

fn load_prepared(
    connection: &Connection,
    call_id: ProviderCallId,
) -> Result<Option<PreparedProviderRecord>, ProviderStoreError> {
    let stored = connection
        .query_row(
            "SELECT prepared_digest, render_digest, profile_digest, record_digest
             FROM provider_prepared_requests WHERE call_id = ?1",
            [call_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderStoreError::CorruptData)?;
    let Some((prepared, render, profile, stored_digest)) = stored else {
        return Ok(None);
    };
    let record = PreparedProviderRecord {
        call_id,
        prepared_digest: fixed_bytes(prepared)?,
        render_digest: fixed_bytes(render)?,
        profile_digest: fixed_bytes(profile)?,
    };
    if fixed_bytes::<32>(stored_digest)? != prepared_record_digest(&record) {
        return Err(ProviderStoreError::CorruptData);
    }
    Ok(Some(record))
}

fn insert_dispatch(
    transaction: &Transaction<'_>,
    claim: &ProviderDispatchClaim,
) -> Result<(), ProviderStoreError> {
    let fencing_token =
        i64::try_from(claim.fencing_token).map_err(|_| ProviderStoreError::StaleFencingToken)?;
    transaction
        .execute(
            "INSERT INTO provider_dispatch_attempts
             (attempt_id, call_id, permit_id, token_reservation_id,
              cost_reservation_id, fencing_token, provider_idempotency_key,
              prepared_digest, render_digest, profile_digest, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.call_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                fencing_token,
                claim.provider_idempotency_key,
                claim.prepared_digest.as_slice(),
                claim.render_digest.as_slice(),
                claim.profile_digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderStoreError::Unavailable)?;
    Ok(())
}

fn load_dispatch_by_attempt(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
    connection
        .query_row(
            "SELECT attempt_id, call_id, permit_id, token_reservation_id,
                    cost_reservation_id, fencing_token, provider_idempotency_key,
                    prepared_digest, render_digest, profile_digest, state,
                    stream_id, settlement_digest
             FROM provider_dispatch_attempts WHERE attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
            decode_dispatch_row,
        )
        .optional()
        .map_err(|_| ProviderStoreError::CorruptData)
}

fn load_dispatch_by_call(
    connection: &Connection,
    call_id: ProviderCallId,
) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
    connection
        .query_row(
            "SELECT attempt_id, call_id, permit_id, token_reservation_id,
                    cost_reservation_id, fencing_token, provider_idempotency_key,
                    prepared_digest, render_digest, profile_digest, state,
                    stream_id, settlement_digest
             FROM provider_dispatch_attempts WHERE call_id = ?1",
            [call_id.as_bytes().as_slice()],
            decode_dispatch_row,
        )
        .optional()
        .map_err(|_| ProviderStoreError::CorruptData)
}

fn decode_dispatch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProviderDispatchRecord> {
    let attempt_id = fixed_bytes_sql::<16>(row.get(0)?)?;
    let call_id = fixed_bytes_sql::<16>(row.get(1)?)?;
    let permit_id = fixed_bytes_sql::<16>(row.get(2)?)?;
    let token_reservation_id = fixed_bytes_sql::<16>(row.get(3)?)?;
    let cost_reservation_id = fixed_bytes_sql::<16>(row.get(4)?)?;
    let fencing_token: i64 = row.get(5)?;
    let state = decode_state(row.get(10)?)?;
    let stream_id = row
        .get::<_, Option<Vec<u8>>>(11)?
        .map(fixed_bytes_sql::<16>)
        .transpose()?
        .map(ProviderStreamId::from_bytes);
    let settlement_digest = row
        .get::<_, Option<Vec<u8>>>(12)?
        .map(fixed_bytes_sql::<32>)
        .transpose()?;
    Ok(ProviderDispatchRecord {
        attempt_id: DispatchAttemptId::from_bytes(attempt_id),
        call_id: ProviderCallId::from_bytes(call_id),
        state,
        stream_id,
        settlement_digest,
        fencing_token: u64::try_from(fencing_token).map_err(|_| rusqlite::Error::InvalidQuery)?,
        permit_id,
        token_reservation_id,
        cost_reservation_id,
        provider_idempotency_key: row.get(6)?,
        prepared_digest: fixed_bytes_sql(row.get(7)?)?,
        render_digest: fixed_bytes_sql(row.get(8)?)?,
        profile_digest: fixed_bytes_sql(row.get(9)?)?,
    })
}

fn decode_state(value: i64) -> rusqlite::Result<ProviderDispatchState> {
    match value {
        1 => Ok(ProviderDispatchState::Dispatching),
        2 => Ok(ProviderDispatchState::Streaming),
        3 => Ok(ProviderDispatchState::Settled),
        4 => Ok(ProviderDispatchState::Uncertain),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn dispatch_matches_claim(record: &ProviderDispatchRecord, claim: &ProviderDispatchClaim) -> bool {
    record.call_id == claim.call_id
        && record.permit_id == claim.permit_id
        && record.token_reservation_id == claim.token_reservation_id
        && record.cost_reservation_id == claim.cost_reservation_id
        && record.fencing_token == claim.fencing_token
        && record.provider_idempotency_key == claim.provider_idempotency_key
        && record.prepared_digest == claim.prepared_digest
        && record.render_digest == claim.render_digest
        && record.profile_digest == claim.profile_digest
}

fn verify_fence(
    record: &ProviderDispatchRecord,
    fencing_token: u64,
) -> Result<(), ProviderStoreError> {
    if fencing_token == 0 || record.fencing_token != fencing_token {
        Err(ProviderStoreError::StaleFencingToken)
    } else {
        Ok(())
    }
}

const fn repository_state(state: ProviderDispatchState) -> ProviderRepositoryState {
    match state {
        ProviderDispatchState::Dispatching => ProviderRepositoryState::Dispatching,
        ProviderDispatchState::Streaming => ProviderRepositoryState::Streaming,
        ProviderDispatchState::Settled => ProviderRepositoryState::Settled,
        ProviderDispatchState::Uncertain => ProviderRepositoryState::Uncertain,
    }
}

const fn repository_error(error: ProviderStoreError) -> ProviderRepositoryError {
    match error {
        ProviderStoreError::Unavailable => ProviderRepositoryError::Unavailable,
        ProviderStoreError::CorruptData => ProviderRepositoryError::CorruptData,
        ProviderStoreError::PreparedMismatch => ProviderRepositoryError::PreparedMismatch,
        ProviderStoreError::StaleFencingToken => ProviderRepositoryError::StaleFencingToken,
        ProviderStoreError::PreparedConflict
        | ProviderStoreError::ClaimConflict
        | ProviderStoreError::NotFound
        | ProviderStoreError::StreamConflict
        | ProviderStoreError::SettlementConflict
        | ProviderStoreError::AlreadyTerminal
        | ProviderStoreError::RecoveryConflict
        | ProviderStoreError::InvalidIdempotencyKey => ProviderRepositoryError::Conflict,
    }
}

fn fixed_bytes<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], ProviderStoreError> {
    bytes
        .try_into()
        .map_err(|_| ProviderStoreError::CorruptData)
}

fn fixed_bytes_sql<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
