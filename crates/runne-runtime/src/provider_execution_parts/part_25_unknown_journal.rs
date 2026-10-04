fn journal_records_digest(records: &[ProviderJournalAppendRequest]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"GOCODE_PROVIDER_UNKNOWN_JOURNAL_SNAPSHOT_V1\0");
    digest.update((records.len() as u64).to_be_bytes());
    for record in records {
        digest.update(record.attempt_id.as_bytes());
        digest.update(record.fencing_token.to_be_bytes());
        digest.update(record.sequence.to_be_bytes());
        digest.update([record.event_kind, u8::from(record.terminal)]);
        digest.update(match record.call_digest_version {
            ProviderCallDigestVersion::V1 => [1],
            ProviderCallDigestVersion::V2 => [2],
        });
        digest.update(record.runtime_generation.to_be_bytes());
        digest.update(record.profile_digest);
        digest.update(record.key.key_id());
        digest.update(record.key.key_version().to_be_bytes());
        digest.update(record.key.runtime_authority_id());
        digest.update(record.key.database_generation().to_be_bytes());
        digest.update(record.encrypted.nonce());
        digest.update((record.encrypted.ciphertext().len() as u64).to_be_bytes());
        digest.update(record.encrypted.ciphertext());
        digest.update(record.encrypted.plaintext_len().to_be_bytes());
        digest.update(record.encrypted.plaintext_digest());
    }
    digest.finalize().into()
}

fn decrypt_unknown_snapshot(
    records: &[ProviderJournalAppendRequest],
    keys: &[(ProviderJournalKeyBinding, ProviderJournalKeyMaterial)],
) -> Result<Vec<ProviderStreamEvent>, ProviderExecutionError> {
    let first = records
        .first()
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    records
        .iter()
        .map(|record| {
            let material = keys
                .iter()
                .find(|(binding, _)| *binding == record.key)
                .map(|(_, material)| material)
                .ok_or(ProviderExecutionError::JournalKeyUnavailable)?;
            let context = ProviderEventJournalContext {
                attempt_id: record.attempt_id,
                fencing_token: record.fencing_token,
                call_digest_version: record.call_digest_version,
                profile_digest: record.profile_digest,
                runtime_generation: record.runtime_generation,
            };
            let aad = event_aad(
                &context,
                record.key,
                record.sequence,
                record.event_kind,
                record.terminal,
            );
            let plaintext = Zeroizing::new(
                open_payload(material, &aad, &record.encrypted)
                    .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
            );
            let event: ProviderStreamEvent = serde_json::from_slice(&plaintext)
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
            if event.sequence() != record.sequence
                || event_kind_code(event.kind()) != record.event_kind
                || matches!(
                    event.kind(),
                    ProviderStreamEventKind::Finished { .. }
                        | ProviderStreamEventKind::ScannerCompleted { .. }
                ) != record.terminal
                || record.attempt_id != first.attempt_id
                || record.fencing_token != first.fencing_token
                || record.call_digest_version != first.call_digest_version
                || record.profile_digest != first.profile_digest
                || record.runtime_generation != first.runtime_generation
            {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
            Ok(event)
        })
        .collect()
}
