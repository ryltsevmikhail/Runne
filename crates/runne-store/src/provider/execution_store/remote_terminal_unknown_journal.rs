fn load_encrypted_events_in_transaction(
    connection: &Connection,
    attempt: &ExecutionAttempt,
) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
    let mut statement = connection
        .prepare(
            "SELECT journal.sequence,journal.key_id,journal.key_version,
                    keys.runtime_authority_id,keys.database_generation,journal.nonce,
                    journal.call_digest_version,journal.profile_digest,journal.runtime_generation,
                    journal.event_kind,journal.terminal,journal.ciphertext,journal.plaintext_len,
                    journal.plaintext_digest
             FROM provider_stream_journal journal
             JOIN provider_journal_key_refs keys
               ON keys.key_id=journal.key_id AND keys.key_version=journal.key_version
             WHERE journal.dispatch_attempt_id=?1 ORDER BY journal.sequence",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map([attempt.dispatch_attempt_id.as_bytes().as_slice()], |row| {
            let key = ProviderJournalKeyBinding::new(
                fixed_bytes(row.get(1)?)?,
                positive_u64(row.get(2)?)?,
                fixed_bytes(row.get(3)?)?,
                positive_u64(row.get(4)?)?,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let encrypted = ProviderEncryptedPayload::new(
                fixed_bytes(row.get(5)?)?,
                row.get(11)?,
                nonnegative_u64(row.get(12)?)?,
                fixed_bytes(row.get(13)?)?,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(ProviderJournalAppendRequest {
                attempt_id: attempt.dispatch_attempt_id,
                fencing_token: attempt.fencing_token,
                sequence: nonnegative_u64(row.get(0)?)?,
                event_kind: u8::try_from(row.get::<_, i64>(9)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                terminal: decode_bool(row.get(10)?)?,
                call_digest_version: decode_call_digest_version(row.get(6)?)?,
                profile_digest: fixed_bytes(row.get(7)?)?,
                runtime_generation: positive_u64(row.get(8)?)?,
                key,
                encrypted,
            })
        })
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if rows.is_empty()
        || rows.iter().enumerate().any(|(sequence, row)| {
            row.sequence != sequence as u64
                || row.profile_digest != attempt.profile_digest
                || row.runtime_generation != attempt.generation
                || row.call_digest_version != attempt.call_digest_version
                || row.key.runtime_authority_id() != attempt.runtime_authority_id
                || row.key.database_generation() != attempt.database_generation
        })
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(rows)
}
