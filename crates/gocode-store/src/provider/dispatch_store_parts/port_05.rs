
fn load_dispatch_by_attempt(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
    connection
        .query_row(
            "SELECT dispatch.attempt_id, dispatch.call_id, dispatch.permit_id,
                    dispatch.token_reservation_id, dispatch.cost_reservation_id,
                    dispatch.fencing_token, dispatch.provider_idempotency_key,
                    dispatch.prepared_digest, dispatch.render_digest,
                    dispatch.profile_digest, dispatch.state, dispatch.stream_id,
                    dispatch.settlement_digest, dispatch.pre_effect_rejection,
                    prepared.call_digest_version, prepared.record_digest
             FROM provider_dispatch_attempts AS dispatch
             JOIN provider_prepared_requests AS prepared
               ON prepared.call_id = dispatch.call_id
             WHERE dispatch.attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
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
    let pre_effect_rejection = row
        .get::<_, Option<i64>>(13)?
        .map(decode_pre_effect_rejection)
        .transpose()?;
    let call_digest_version = decode_digest_version_sql(row.get(14)?)?;
    let prepared_digest = fixed_bytes_sql(row.get(7)?)?;
    let render_digest = fixed_bytes_sql(row.get(8)?)?;
    let profile_digest = fixed_bytes_sql(row.get(9)?)?;
    let prepared = PreparedProviderRecord {
        call_id: ProviderCallId::from_bytes(call_id),
        call_digest_version,
        prepared_digest,
        render_digest,
        profile_digest,
    };
    if fixed_bytes_sql::<32>(row.get(15)?)? != prepared_record_digest(&prepared) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let record = ProviderDispatchRecord {
        attempt_id: DispatchAttemptId::from_bytes(attempt_id),
        call_id: ProviderCallId::from_bytes(call_id),
        state,
        stream_id,
        settlement_digest,
        pre_effect_rejection,
        call_digest_version,
        fencing_token: u64::try_from(fencing_token).map_err(|_| rusqlite::Error::InvalidQuery)?,
        permit_id,
        token_reservation_id,
        cost_reservation_id,
        provider_idempotency_key: row.get(6)?,
        prepared_digest,
        render_digest,
        profile_digest,
    };
    if dispatch_record_shape_is_valid(&record) {
        Ok(record)
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

fn dispatch_record_shape_is_valid(record: &ProviderDispatchRecord) -> bool {
    match record.state {
        ProviderDispatchState::Dispatching => {
            record.stream_id.is_none()
                && record.settlement_digest.is_none()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::RejectedBeforeEffect => {
            record.stream_id.is_none()
                && record.settlement_digest.is_none()
                && record.pre_effect_rejection.is_some()
        }
        ProviderDispatchState::Streaming => {
            record.stream_id.is_some()
                && record.settlement_digest.is_none()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::TerminalPendingCommit => {
            record.stream_id.is_some()
                && record.settlement_digest.is_some()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::Settled => {
            (record.stream_id.is_some()
                || record.call_digest_version == ProviderCallDigestVersion::V1)
                && record.settlement_digest.is_some()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::Uncertain => {
            record.pre_effect_rejection.is_none()
                && (record.settlement_digest.is_none() || record.stream_id.is_some())
        }
    }
}

fn decode_digest_version_sql(value: i64) -> rusqlite::Result<ProviderCallDigestVersion> {
    match value {
        1 => Ok(ProviderCallDigestVersion::V1),
        2 => Ok(ProviderCallDigestVersion::V2),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn decode_state(value: i64) -> rusqlite::Result<ProviderDispatchState> {
    match value {
        1 => Ok(ProviderDispatchState::Dispatching),
        2 => Ok(ProviderDispatchState::RejectedBeforeEffect),
        3 => Ok(ProviderDispatchState::Streaming),
        4 => Ok(ProviderDispatchState::TerminalPendingCommit),
        5 => Ok(ProviderDispatchState::Settled),
        6 => Ok(ProviderDispatchState::Uncertain),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

const fn encode_pre_effect_rejection(rejection: ProviderPreEffectRejection) -> i64 {
    match rejection {
        ProviderPreEffectRejection::CredentialUnavailable => 1,
        ProviderPreEffectRejection::CredentialAccessDenied => 2,
        ProviderPreEffectRejection::ProfileRejected => 3,
        ProviderPreEffectRejection::CapabilityDenied => 4,
        ProviderPreEffectRejection::BudgetDenied => 5,
        ProviderPreEffectRejection::AdmissionRejected => 6,
        ProviderPreEffectRejection::AdapterRejected => 7,
    }
}

fn decode_pre_effect_rejection(value: i64) -> rusqlite::Result<ProviderPreEffectRejection> {
    match value {
        1 => Ok(ProviderPreEffectRejection::CredentialUnavailable),
        2 => Ok(ProviderPreEffectRejection::CredentialAccessDenied),
        3 => Ok(ProviderPreEffectRejection::ProfileRejected),
        4 => Ok(ProviderPreEffectRejection::CapabilityDenied),
        5 => Ok(ProviderPreEffectRejection::BudgetDenied),
        6 => Ok(ProviderPreEffectRejection::AdmissionRejected),
        7 => Ok(ProviderPreEffectRejection::AdapterRejected),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
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
        ProviderDispatchState::RejectedBeforeEffect => {
            ProviderRepositoryState::RejectedBeforeEffect
        }
        ProviderDispatchState::Streaming => ProviderRepositoryState::Streaming,
        ProviderDispatchState::TerminalPendingCommit => {
            ProviderRepositoryState::TerminalPendingCommit
        }
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
        | ProviderStoreError::RejectionConflict
        | ProviderStoreError::SettlementBeforeStreaming
        | ProviderStoreError::SettlementBeforeTerminal
        | ProviderStoreError::AlreadyTerminal
        | ProviderStoreError::RecoveryConflict
        | ProviderStoreError::InvalidIdempotencyKey
        | ProviderStoreError::LegacyClaimDisabled => ProviderRepositoryError::Conflict,
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
