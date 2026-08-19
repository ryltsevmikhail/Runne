fn seal_payload_with_nonce(
    material: &ProviderJournalKeyMaterial,
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<ProviderEncryptedPayload, RuntimeProviderExecutionError> {
    let mut ciphertext = plaintext.to_vec();
    material.with_bytes(|bytes| {
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
            .map_err(|_| RuntimeProviderExecutionError::JournalKeyUnavailable)?;
        LessSafeKey::new(unbound)
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)
    })?;
    ProviderEncryptedPayload::new(
        nonce,
        ciphertext,
        u64::try_from(plaintext.len())
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?,
        Sha256::digest(plaintext).into(),
    )
    .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)
}

fn open_payload(
    material: &ProviderJournalKeyMaterial,
    aad: &[u8],
    encrypted: &ProviderEncryptedPayload,
) -> Result<Vec<u8>, RuntimeProviderExecutionError> {
    let mut plaintext = encrypted.ciphertext().to_vec();
    let opened_len = material.with_bytes(|bytes| {
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
            .map_err(|_| RuntimeProviderExecutionError::JournalKeyUnavailable)?;
        let opened = LessSafeKey::new(unbound)
            .open_in_place(
                Nonce::assume_unique_for_key(*encrypted.nonce()),
                Aad::from(aad),
                &mut plaintext,
            )
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
        Ok::<usize, RuntimeProviderExecutionError>(opened.len())
    })?;
    plaintext.truncate(opened_len);
    if plaintext.len()
        != usize::try_from(encrypted.plaintext_len())
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?
        || Sha256::digest(&plaintext).as_slice() != encrypted.plaintext_digest()
    {
        return Err(RuntimeProviderExecutionError::JournalCorrupt);
    }
    Ok(plaintext)
}

fn event_aad(
    context: &ProviderEventJournalContext,
    key: ProviderJournalKeyBinding,
    sequence: u64,
    event_kind: u8,
    terminal: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(192);
    aad.extend_from_slice(PROVIDER_JOURNAL_AAD_V1);
    push_common_aad(&mut aad, context, key, sequence);
    aad.push(event_kind);
    aad.push(u8::from(terminal));
    aad
}

fn outbox_aad(
    context: &ProviderEventJournalContext,
    key: ProviderJournalKeyBinding,
    terminal_sequence: u64,
    outbox_id: [u8; 16],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(208);
    aad.extend_from_slice(PROVIDER_OUTBOX_AAD_V1);
    push_common_aad(&mut aad, context, key, terminal_sequence);
    aad.extend_from_slice(&outbox_id);
    aad
}

fn push_common_aad(
    aad: &mut Vec<u8>,
    context: &ProviderEventJournalContext,
    key: ProviderJournalKeyBinding,
    sequence: u64,
) {
    aad.extend_from_slice(context.attempt_id.as_bytes());
    aad.extend_from_slice(&context.fencing_token.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&key.key_id());
    aad.extend_from_slice(&key.key_version().to_be_bytes());
    aad.extend_from_slice(&key.runtime_authority_id());
    aad.extend_from_slice(&key.database_generation().to_be_bytes());
    aad.push(match context.call_digest_version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    });
    aad.extend_from_slice(&context.profile_digest);
    aad.extend_from_slice(&context.runtime_generation.to_be_bytes());
}

fn event_kind_code(kind: &ProviderStreamEventKind) -> u8 {
    match kind {
        ProviderStreamEventKind::Started => 1,
        ProviderStreamEventKind::TextDelta { .. } => 2,
        ProviderStreamEventKind::Usage { .. } => 3,
        ProviderStreamEventKind::ToolCallRequested { .. } => 4,
        ProviderStreamEventKind::Finished { .. } => 5,
        ProviderStreamEventKind::UsageUnavailable => 6,
        ProviderStreamEventKind::ScannerCompleted { .. } => 5,
        ProviderStreamEventKind::ScannerProgress => 7,
    }
}

fn secure_ref_from_binding(
    binding: ProviderJournalKeyBinding,
) -> Result<ProviderJournalKeyRef, RuntimeProviderExecutionError> {
    ProviderJournalKeyRef::new(
        binding.key_id(),
        binding.key_version(),
        binding.runtime_authority_id(),
        binding.database_generation(),
    )
    .map_err(map_secure_store_error)
}

fn binding_from_secure_ref(
    key_ref: ProviderJournalKeyRef,
) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
    ProviderJournalKeyBinding::new(
        key_ref.key_id(),
        key_ref.version(),
        key_ref.runtime_authority_id(),
        key_ref.database_generation(),
    )
    .map_err(map_execution_error)
}

fn map_secure_store_error(error: SecureStoreError) -> RuntimeProviderExecutionError {
    match error {
        SecureStoreError::RetentionUnsupported => {
            RuntimeProviderExecutionError::KeyRetentionUnsupported
        }
        _ => RuntimeProviderExecutionError::JournalKeyUnavailable,
    }
}

fn map_execution_error(error: ProviderExecutionError) -> RuntimeProviderExecutionError {
    match error {
        ProviderExecutionError::JournalKeyUnavailable => {
            RuntimeProviderExecutionError::JournalKeyUnavailable
        }
        ProviderExecutionError::JournalCorrupt
        | ProviderExecutionError::NonceReuse
        | ProviderExecutionError::SequenceMismatch => RuntimeProviderExecutionError::JournalCorrupt,
        ProviderExecutionError::StaleGeneration
        | ProviderExecutionError::AttemptUncertain
        | ProviderExecutionError::PollNotArmed => RuntimeProviderExecutionError::RecoveryFrozen,
        ProviderExecutionError::TerminalConflict
        | ProviderExecutionError::ReservationMismatch
        | ProviderExecutionError::OutboxConflict => RuntimeProviderExecutionError::TerminalRejected,
        ProviderExecutionError::StoreUnavailable => {
            RuntimeProviderExecutionError::PersistenceUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_aad_database_generation_and_ciphertext_fail_authentication() {
        let key_ref = ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 3).unwrap();
        let material = ProviderJournalKeyMaterial::new(key_ref, [4; 32]).unwrap();
        let context = ProviderEventJournalContext {
            attempt_id: DispatchAttemptId::from_bytes([5; 16]),
            fencing_token: 6,
            call_digest_version: ProviderCallDigestVersion::V2,
            profile_digest: [7; 32],
            runtime_generation: 8,
        };
        let key = binding_from_secure_ref(key_ref).unwrap();
        let aad = event_aad(&context, key, 0, 2, false);
        let encrypted =
            seal_payload_with_nonce(&material, [9; 12], &aad, b"authenticated-event").unwrap();
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&context, key, 0, 3, false),
                &encrypted,
            ),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );

        let wrong_generation = ProviderJournalKeyBinding::new([1; 16], 1, [2; 16], 4).unwrap();
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&context, wrong_generation, 0, 2, false),
                &encrypted,
            ),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );

        let wrong_fence = ProviderEventJournalContext {
            fencing_token: context.fencing_token + 1,
            ..context
        };
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&wrong_fence, key, 0, 2, false),
                &encrypted,
            ),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );

        let mut corrupt = encrypted.clone();
        let mut bytes = corrupt.ciphertext().to_vec();
        bytes[0] ^= 1;
        corrupt = ProviderEncryptedPayload::new(
            *corrupt.nonce(),
            bytes,
            corrupt.plaintext_len(),
            *corrupt.plaintext_digest(),
        )
        .unwrap();
        assert_eq!(
            open_payload(&material, &aad, &corrupt),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );
    }
}
