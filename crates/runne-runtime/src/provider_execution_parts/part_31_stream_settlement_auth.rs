fn verify_authenticated_stream_settlement<K: ProviderJournalKeyring + ?Sized>(
    keyring: &K,
    binding: &runne_application::provider::ProviderRemoteAttemptBinding,
    candidate: runne_application::provider::ProviderRemoteTerminalSettlementDigestCandidate<'_>,
    journal: &[ProviderJournalAppendRequest],
    kind: ProviderTerminalApplicationKind,
) -> Result<bool, ProviderRecoveryError> {
    let assembled = authenticate_stream_journal(keyring, binding, journal, kind)?;
    if assembled.usage.exact() != Some(candidate.usage)
        || terminal_disposition_code(assembled.disposition)
            != match candidate.status {
                ProviderRemoteTerminalDisposition::Completed => 1,
                ProviderRemoteTerminalDisposition::Failed => 2,
                ProviderRemoteTerminalDisposition::Incomplete => 3,
                ProviderRemoteTerminalDisposition::Cancelled => 4,
            }
    {
        return Ok(false);
    }
    let first = journal
        .first()
        .ok_or(ProviderRecoveryError::InvalidIdentity)?;
    let context = ProviderEventJournalContext {
        attempt_id: binding.dispatch_attempt_id,
        fencing_token: binding.fencing_token,
        call_digest_version: first.call_digest_version,
        profile_digest: binding.profile_digest,
        runtime_generation: binding.runtime_generation,
    };
    let digest = application_settlement_digest(
        kind,
        stream_settlement_digest(
            &context,
            &binding.pricing_digest,
            assembled.terminal_sequence,
            &assembled.output,
            candidate.usage,
            false,
            assembled.disposition,
            candidate.charge_micros,
            candidate.currency,
        ),
    );
    Ok(digest == *candidate.settlement_digest)
}

fn authenticate_stream_journal<K: ProviderJournalKeyring + ?Sized>(
    keyring: &K,
    binding: &runne_application::provider::ProviderRemoteAttemptBinding,
    journal: &[ProviderJournalAppendRequest],
    kind: ProviderTerminalApplicationKind,
) -> Result<AssembledTerminal, ProviderRecoveryError> {
    let invalid = || ProviderRecoveryError::InvalidIdentity;
    let first = journal.first().ok_or_else(invalid)?;
    if journal.len() > 4096
        || journal.iter().enumerate().any(|(i, row)| {
            row.sequence != i as u64
                || row.attempt_id != binding.dispatch_attempt_id
                || row.fencing_token != binding.fencing_token
                || row.profile_digest != binding.profile_digest
                || row.runtime_generation != binding.runtime_generation
                || row.key.runtime_authority_id() != binding.runtime_authority_id
                || row.key.database_generation() != binding.database_generation
                || row.call_digest_version != first.call_digest_version
        })
    {
        return Err(invalid());
    }
    let mut keys = Vec::new();
    for row in journal {
        if keys.iter().any(|(key, _)| *key == row.key) {
            continue;
        }
        let key = secure_ref_from_binding(row.key).map_err(|_| invalid())?;
        let material = keyring
            .load_provider_journal_key(key)
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        keys.push((row.key, material));
    }
    let events = decrypt_unknown_snapshot(journal, &keys).map_err(|_| invalid())?;
    match kind {
        ProviderTerminalApplicationKind::TextGeneration => assemble_terminal_stream(&events),
        ProviderTerminalApplicationKind::ToolProposal => assemble_terminal_stream_mode(
            &events,
            true,
            if binding.profile_id == "runne-deepseek-responses-tools/1" {
                16
            } else {
                1
            },
        ),
    }
    .map_err(|_| invalid())
}

#[cfg(test)]
#[path = "part_31_stream_settlement_auth_tests.rs"]
mod stream_settlement_auth_tests;

impl<K, S> RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized,
{
    fn authenticate_stream_request(
        &self,
        snapshot: &ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
    ) -> Result<(), ProviderRecoveryError> {
        let binding = &snapshot.request.binding;
        self.authenticate_remote_terminal_snapshot(
            snapshot,
            expected,
            binding.taskrun_id,
            binding.taskrun_attempt_id,
        )?;
        let attempt = ProviderRecoveryBinding::new(
            binding.taskrun_id,
            binding.taskrun_attempt_id,
            binding.dispatch_attempt_id,
            binding.profile_digest,
        )?;
        let key = self
            .keyring
            .load_provider_journal_key(
                secure_ref_from_binding(snapshot.request.key)
                    .map_err(|_| ProviderRecoveryError::InvalidIdentity)?,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let rendered = Zeroizing::new(
            open_payload(
                &key,
                &remote_request_aad(attempt, expected, snapshot.request.key),
                &snapshot.request.encrypted_request,
            )
            .map_err(|_| ProviderRecoveryError::InvalidIdentity)?,
        );
        if Sha256::digest(rendered.as_slice()).as_slice() != expected.request_digest() {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        Ok(())
    }
}
