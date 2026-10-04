use ring::hmac;

const UNKNOWN_KEY_DERIVATION_V1: &[u8] = b"GOCODE_PROVIDER_UNKNOWN_KEY_DERIVATION_V1\0";
const UNKNOWN_RECEIPT_MAC_V1: &[u8] = b"GOCODE_PROVIDER_UNKNOWN_RECEIPT_MAC_V1\0";

struct RuntimeUnknownAuthenticator<'a> {
    selector: ProviderTerminalUnknownSelector,
    context: ProviderEventJournalContext,
    journal_digest: [u8; 32],
    keys: &'a [(ProviderJournalKeyBinding, ProviderJournalKeyMaterial)],
    reason: Option<ProviderUnknownAccountingReason>,
    disposition: ProviderTerminalDisposition,
    usage: Option<ProviderUsage>,
    output: Option<ProviderEncryptedPayload>,
    outbox_id: [u8; 16],
}

impl unknown_auth_private::Sealed for RuntimeUnknownAuthenticator<'_> {}

impl ProviderUnknownTerminalAuthenticator for RuntimeUnknownAuthenticator<'_> {
    fn authenticate(
        &self,
        snapshot: &ProviderUnknownTerminalSnapshot,
    ) -> Result<ProviderUnknownTerminalAuthorization, ProviderExecutionError> {
        let first = snapshot
            .journal()
            .first()
            .ok_or(ProviderExecutionError::JournalCorrupt)?;
        if snapshot.selector() != self.selector
            || snapshot.context() != self.context
            || journal_records_digest(snapshot.journal()) != self.journal_digest
            || first.attempt_id != snapshot.context().attempt_id
            || first.fencing_token != snapshot.context().fencing_token
            || first.call_digest_version != snapshot.context().call_digest_version
            || first.profile_digest != snapshot.context().profile_digest
            || first.runtime_generation != snapshot.context().runtime_generation
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let events = decrypt_unknown_snapshot(snapshot.journal(), self.keys)?;
        let assembled = assemble_terminal_stream(&events)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        if assembled.terminal_sequence != self.selector.terminal_sequence()
            || assembled.disposition != self.disposition
            || assembled.usage.exact() != self.usage
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let reason = snapshot
            .current()
            .existing_unknown_reason
            .or(self.reason)
            .ok_or(ProviderExecutionError::TerminalConflict)?;
        if snapshot.current().existing_unknown_reason.is_some()
            && (snapshot.current().existing_unknown_usage != self.usage
                || snapshot.current().existing_unknown_disposition != Some(self.disposition))
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        if snapshot.current().existing_unknown_reason.is_some()
            && self.reason.is_some_and(|candidate| candidate != reason)
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        if matches!(reason, ProviderUnknownAccountingReason::UsageUnavailable)
            != self.usage.is_none()
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let selected_output = snapshot
            .current()
            .existing_completed_output
            .as_ref()
            .or(self.output.as_ref());
        let output_identity = snapshot
            .current()
            .existing_outbox_id
            .unwrap_or(self.outbox_id);
        let (published_outbox_id, application_idempotency_key) =
            if snapshot.current().existing_unknown_commitment.is_some() {
                (
                    snapshot.current().existing_outbox_id,
                    snapshot
                        .current()
                        .existing_application_idempotency_key
                        .clone(),
                )
            } else if self.disposition == ProviderTerminalDisposition::Completed
                && snapshot.original().publication_allowed
                && snapshot.current().output_publication_allowed
            {
                (
                    Some(self.outbox_id),
                    Some(terminal_application_key(self.selector.attempt_id())),
                )
            } else {
                (None, None)
            };
        if published_outbox_id.is_some() != application_idempotency_key.is_some() {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        if snapshot.current().existing_unknown_commitment.is_some()
            && ((self.disposition == ProviderTerminalDisposition::Completed)
                != selected_output.is_some())
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        if snapshot.current().existing_unknown_commitment.is_none()
            && snapshot.current().existing_completed_output.is_some()
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let output_matches = selected_output.is_some_and(|payload| {
            usize::try_from(payload.plaintext_len()).ok() == Some(assembled.output.len())
                && Sha256::digest(assembled.output.as_slice()).as_slice()
                    == payload.plaintext_digest()
        });
        if self.disposition == ProviderTerminalDisposition::Completed {
            if !output_matches {
                return Err(ProviderExecutionError::TerminalConflict);
            }
            if let Some(existing) = snapshot.current().existing_completed_output.as_ref() {
                let record = snapshot
                    .journal()
                    .iter()
                    .find(|record| record.sequence == self.selector.terminal_sequence())
                    .ok_or(ProviderExecutionError::JournalCorrupt)?;
                let key = self
                    .keys
                    .iter()
                    .find(|(binding, _)| *binding == record.key)
                    .map(|(_, material)| material)
                    .ok_or(ProviderExecutionError::JournalKeyUnavailable)?;
                let outbox_aad = outbox_aad(
                    &snapshot.context(),
                    record.key,
                    self.selector.terminal_sequence(),
                    output_identity,
                );
                let plaintext = open_payload(key, &outbox_aad, existing)
                    .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
                if plaintext.as_slice() != assembled.output.as_slice() {
                    return Err(ProviderExecutionError::TerminalConflict);
                }
            }
        } else if selected_output.is_some() {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let source_binding_digest =
            Sha256::digest(encode_unknown_source_binding(snapshot.original())).into();
        let journal_digest = journal_records_digest(snapshot.journal());
        let commitment = unknown_terminal_mac(
            self.keys,
            snapshot,
            reason,
            self.disposition,
            self.usage,
            selected_output,
            output_identity,
            published_outbox_id,
            application_idempotency_key.as_deref(),
        )?;
        Ok(ProviderUnknownTerminalAuthorization {
            attempt_id: self.selector.attempt_id(),
            terminal_sequence: self.selector.terminal_sequence(),
            reason,
            disposition: self.disposition,
            usage: self.usage,
            encrypted_output: selected_output.cloned(),
            outbox_id: output_identity,
            published_outbox_id,
            application_idempotency_key,
            journal_digest,
            source_binding_digest,
            commitment,
        })
    }
}

fn unknown_terminal_mac(
    keys: &[(ProviderJournalKeyBinding, ProviderJournalKeyMaterial)],
    snapshot: &ProviderUnknownTerminalSnapshot,
    reason: ProviderUnknownAccountingReason,
    disposition: ProviderTerminalDisposition,
    usage: Option<ProviderUsage>,
    output: Option<&ProviderEncryptedPayload>,
    outbox_id: [u8; 16],
    published_outbox_id: Option<[u8; 16]>,
    application_idempotency_key: Option<&str>,
) -> Result<[u8; 32], ProviderExecutionError> {
    let terminal_key = snapshot
        .journal()
        .iter()
        .find(|row| row.sequence == snapshot.selector().terminal_sequence())
        .ok_or(ProviderExecutionError::JournalCorrupt)?
        .key;
    let material = keys
        .iter()
        .find(|(binding, _)| *binding == terminal_key)
        .map(|(_, material)| material)
        .ok_or(ProviderExecutionError::JournalKeyUnavailable)?;
    let key_ref = terminal_key;
    let mut derivation = Vec::from(UNKNOWN_KEY_DERIVATION_V1);
    derivation.extend_from_slice(&key_ref.key_id());
    derivation.extend_from_slice(&key_ref.key_version().to_be_bytes());
    derivation.extend_from_slice(&key_ref.runtime_authority_id());
    derivation.extend_from_slice(&key_ref.database_generation().to_be_bytes());
    let derived_tag = material
        .with_bytes(|master| hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, master), &derivation));
    let mut derived = Zeroizing::new([0; 32]);
    derived.copy_from_slice(derived_tag.as_ref());
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(UNKNOWN_RECEIPT_MAC_V1);
    let source_binding = encode_unknown_source_binding(snapshot.original());
    push_unknown_frame(&mut mac_input, &source_binding);
    mac_input.extend_from_slice(snapshot.context().attempt_id.as_bytes());
    mac_input.extend_from_slice(&snapshot.context().fencing_token.to_be_bytes());
    mac_input.extend_from_slice(&snapshot.selector().fencing_token().to_be_bytes());
    mac_input.extend_from_slice(&snapshot.context().runtime_generation.to_be_bytes());
    mac_input.extend_from_slice(&snapshot.context().profile_digest);
    mac_input.push(match snapshot.context().call_digest_version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    });
    mac_input.extend_from_slice(&snapshot.selector().terminal_sequence().to_be_bytes());
    mac_input.extend_from_slice(&journal_records_digest(snapshot.journal()));
    mac_input.extend_from_slice(&outbox_id);
    if let Some(published_outbox_id) = published_outbox_id {
        mac_input.push(1);
        mac_input.extend_from_slice(&published_outbox_id);
    } else {
        mac_input.push(0);
    }
    if let Some(application_idempotency_key) = application_idempotency_key {
        mac_input.push(1);
        push_unknown_frame(&mut mac_input, application_idempotency_key.as_bytes());
    } else {
        mac_input.push(0);
    }
    mac_input.push(unknown_reason_code(reason));
    mac_input.push(terminal_disposition_code(disposition));
    if let Some(value) = usage {
        mac_input.push(1);
        mac_input.extend_from_slice(&value.input_tokens().to_be_bytes());
        mac_input.extend_from_slice(&value.output_tokens().to_be_bytes());
        mac_input.extend_from_slice(&value.cached_input_tokens().to_be_bytes());
        mac_input.extend_from_slice(&value.reasoning_output_tokens().to_be_bytes());
    } else {
        mac_input.push(0);
    }
    if let Some(value) = output {
        mac_input.push(1);
        mac_input.extend_from_slice(value.nonce());
        mac_input.extend_from_slice(&value.plaintext_len().to_be_bytes());
        mac_input.extend_from_slice(value.plaintext_digest());
        push_unknown_frame(&mut mac_input, value.ciphertext());
    } else {
        mac_input.push(0);
    }
    let derived_key = hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref());
    let tag = hmac::sign(&derived_key, &mac_input);
    if let Some(existing) = snapshot.current().existing_unknown_commitment {
        hmac::verify(&derived_key, &mac_input, &existing)
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
    }
    let mut output = [0; 32];
    output.copy_from_slice(tag.as_ref());
    Ok(output)
}
