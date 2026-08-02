
impl ProviderDispatchRepository for SqliteProviderDispatchStore {
    fn load_prepared(
        &self,
        call_id: ProviderCallId,
    ) -> Result<Option<ContractPreparedProviderRecord>, ProviderRepositoryError> {
        SqliteProviderDispatchStore::get_prepared(self, call_id)
            .map(|record| {
                record.map(|record| ContractPreparedProviderRecord {
                    call_id: record.call_id,
                    call_digest_version: record.call_digest_version,
                    prepared_digest: record.prepared_digest,
                    render_digest: record.render_digest,
                    profile_digest: record.profile_digest,
                })
            })
            .map_err(repository_error)
    }

    fn persist_prepared(
        &self,
        record: &ContractPreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::persist_prepared(
            self,
            &PreparedProviderRecord {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn claim(
        &self,
        claim: &ContractProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        SqliteProviderDispatchStore::claim(
            self,
            &ProviderDispatchClaim {
                call_id: claim.call_id,
                attempt_id: claim.attempt_id,
                permit_id: claim.permit_id,
                prepared_digest: claim.prepared_digest,
                render_digest: claim.render_digest,
                profile_digest: claim.profile_digest,
                token_reservation_id: claim.token_reservation_id,
                cost_reservation_id: claim.cost_reservation_id,
                fencing_token: claim.fencing_token,
                provider_idempotency_key: claim.provider_idempotency_key.clone(),
            },
        )
        .map(|outcome| match outcome {
            ProviderClaimOutcome::Winner { permit_id } => {
                ProviderRepositoryClaimOutcome::Winner { permit_id }
            }
            ProviderClaimOutcome::Existing { attempt_id, state } => {
                ProviderRepositoryClaimOutcome::Existing {
                    attempt_id,
                    state: repository_state(state),
                }
            }
        })
        .map_err(repository_error)
    }

    fn mark_streaming(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_streaming(
            self,
            &MarkProviderStreaming {
                attempt_id,
                fencing_token,
                stream_id,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn mark_rejected_before_effect(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        rejection: ProviderPreEffectRejection,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_rejected_before_effect(
            self,
            attempt_id,
            fencing_token,
            rejection,
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn mark_terminal_pending(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_terminal_pending(
            self,
            &SettleProviderDispatch {
                attempt_id,
                fencing_token,
                settlement_digest,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn settle(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::settle(
            self,
            &SettleProviderDispatch {
                attempt_id,
                fencing_token,
                settlement_digest,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn mark_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_uncertain(self, attempt_id, fencing_token)
            .map(|_| ())
            .map_err(repository_error)
    }
}

fn prepared_record_digest(record: &PreparedProviderRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match record.call_digest_version {
        ProviderCallDigestVersion::V1 => hasher.update(PREPARED_V1_DOMAIN),
        ProviderCallDigestVersion::V2 => {
            hasher.update(PREPARED_V2_DOMAIN);
            hasher.update([2]);
        }
    }
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
            "SELECT prepared_digest, render_digest, profile_digest, record_digest,
                    call_digest_version
             FROM provider_prepared_requests WHERE call_id = ?1",
            [call_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderStoreError::CorruptData)?;
    let Some((prepared, render, profile, stored_digest, digest_version)) = stored else {
        return Ok(None);
    };
    let record = PreparedProviderRecord {
        call_id,
        call_digest_version: decode_digest_version(digest_version)?,
        prepared_digest: fixed_bytes(prepared)?,
        render_digest: fixed_bytes(render)?,
        profile_digest: fixed_bytes(profile)?,
    };
    if fixed_bytes::<32>(stored_digest)? != prepared_record_digest(&record) {
        return Err(ProviderStoreError::CorruptData);
    }
    Ok(Some(record))
}

const fn encode_digest_version(version: ProviderCallDigestVersion) -> i64 {
    match version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }
}

fn decode_digest_version(value: i64) -> Result<ProviderCallDigestVersion, ProviderStoreError> {
    match value {
        1 => Ok(ProviderCallDigestVersion::V1),
        2 => Ok(ProviderCallDigestVersion::V2),
        _ => Err(ProviderStoreError::CorruptData),
    }
}
