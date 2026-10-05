impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore
        + ProviderTerminalPersistence
        + runne_application::provider::ProviderRemoteRecoveryStore,
    P: ProviderTerminalPricing,
{
    /// Loads and decrypts pending terminal outputs for idempotent application.
    pub fn recover_pending_terminal_outputs(
        &self,
    ) -> Result<Vec<RecoveredProviderTerminalOutput>, RuntimeProviderExecutionError> {
        let pending = self
            .store
            .pending_terminal_outbox()
            .map_err(map_execution_error)?;
        pending
            .into_iter()
            .map(|record| self.recover_one_terminal_outbox(record))
            .collect()
    }

    fn recover_one_terminal_outbox(
        &self,
        record: ProviderTerminalOutboxRecord,
    ) -> Result<RecoveredProviderTerminalOutput, RuntimeProviderExecutionError> {
        if record.application_kind
            != runne_application::provider::ProviderTerminalApplicationKind::TextGeneration
        {
            return Err(RuntimeProviderExecutionError::ApplicationConflict);
        }
        if let runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact {
            artifact_digest,
        } = record.source
        {
            return recover_remote_artifact_outbox(
                self.keyring,
                self.store,
                record,
                artifact_digest,
            );
        }
        if let runne_application::provider::ProviderTerminalOutboxSource::UnknownJournal {
            commitment,
        } = record.source
        {
            if record.settlement_digest != commitment {
                return Err(RuntimeProviderExecutionError::JournalCorrupt);
            }
            let journal = self
                .store
                .load_encrypted_events(record.attempt_id)
                .map_err(map_execution_error)?;
            let (events, keys) = self.decrypt_terminal_journal(&journal)?;
            let assembled = assemble_terminal_stream(&events)?;
            if assembled.disposition != ProviderTerminalDisposition::Completed
                || !matches!(
                    self.replay_unknown_terminal(
                        &ProviderEventJournalContext {
                            attempt_id: record.attempt_id,
                            fencing_token: record.fencing_token,
                            call_digest_version: record.call_digest_version,
                            profile_digest: record.profile_digest,
                            runtime_generation: record.runtime_generation,
                        },
                        &journal,
                        &keys,
                        &assembled,
                    )?,
                    Some(ProviderTerminalCommitOutcome::Replayed)
                )
            {
                return Err(RuntimeProviderExecutionError::JournalCorrupt);
            }
        }
        if self
            .redaction
            .terminal_disposition(record.attempt_id)
            .map_err(|_| RuntimeProviderExecutionError::PolicyDenied)?
            != Some(runne_provider::ScannerTerminalDisposition::Completed)
        {
            return Err(RuntimeProviderExecutionError::PolicyDenied);
        }
        let material = self.load_key(record.key)?;
        let context = ProviderEventJournalContext {
            attempt_id: record.attempt_id,
            fencing_token: record.fencing_token,
            call_digest_version: record.call_digest_version,
            profile_digest: record.profile_digest,
            runtime_generation: record.runtime_generation,
        };
        let aad = outbox_aad(
            &context,
            record.key,
            record.terminal_sequence,
            record.outbox_id,
        );
        let output = Zeroizing::new(open_payload(&material, &aad, &record.encrypted_output)?);
        Ok(RecoveredProviderTerminalOutput { record, output })
    }
}

fn recover_remote_artifact_outbox<K, S>(
    keyring: &K,
    store: &S,
    record: ProviderTerminalOutboxRecord,
    expected_artifact_digest: [u8; 32],
) -> Result<RecoveredProviderTerminalOutput, RuntimeProviderExecutionError>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + runne_application::provider::ProviderRemoteRecoveryStore + ?Sized,
{
    if record.terminal_sequence != 0
        || record.encrypted_output.plaintext_digest() != &expected_artifact_digest
    {
        return Err(RuntimeProviderExecutionError::JournalCorrupt);
    }
    let snapshot = store
        .load_remote_attempt_snapshot(record.attempt_id)
        .map_err(map_execution_error)?
        .ok_or(RuntimeProviderExecutionError::JournalCorrupt)?;
    let binding = &snapshot.request.binding;
    let admitted_digest_version = store
        .load_remote_call_digest_version(record.attempt_id)
        .map_err(map_execution_error)?;
    if binding.taskrun_id != record.taskrun_id
        || binding.taskrun_attempt_id != record.execution_attempt_id
        || binding.dispatch_attempt_id != record.attempt_id
        || binding.profile_digest != record.profile_digest
        || binding.runtime_generation != record.runtime_generation
        || binding.fencing_token != record.fencing_token
        || admitted_digest_version != record.call_digest_version
        || snapshot.terminal.as_ref().is_none_or(|terminal| {
            terminal.key != record.key || terminal.encrypted_artifact != record.encrypted_output
        })
        || snapshot.terminal.as_ref().is_none_or(|terminal| {
            terminal.encrypted_artifact.plaintext_digest() != &expected_artifact_digest
        })
    {
        return Err(RuntimeProviderExecutionError::JournalCorrupt);
    }
    let identity = ProviderRecoveryAttemptIdentity::new(
        ProviderId::new(&binding.provider_id)
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?,
        ProviderId::new(&binding.credential_realm)
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?,
        binding.profile_id.clone(),
        binding.profile_digest,
        binding.semantic_digest,
        binding.prepared_digest,
        binding.pricing_digest,
        binding.request_digest,
        binding.runtime_authority_id,
        binding.database_generation,
        binding.runtime_generation,
        binding.fencing_token,
    )
    .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
    let artifact = authenticate_remote_terminal_snapshot_with_keyring(
        keyring,
        &snapshot,
        &identity,
        record.taskrun_id,
        record.execution_attempt_id,
    )
    .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?
    .ok_or(RuntimeProviderExecutionError::JournalCorrupt)?;
    if artifact.publication_disposition()
        != runne_provider::ProviderRemotePublicationDisposition::Allowed
        || !matches!(
            artifact.status(),
            runne_provider::ProviderRemoteResponseStatus::Completed { .. }
        )
    {
        return Err(RuntimeProviderExecutionError::PolicyDenied);
    }
    let output = artifact
        .output_text()
        .ok_or(RuntimeProviderExecutionError::PolicyDenied)?;
    if output.len() > 65_536 {
        return Err(RuntimeProviderExecutionError::PolicyDenied);
    }
    Ok(RecoveredProviderTerminalOutput {
        record,
        output: Zeroizing::new(output.as_bytes().to_vec()),
    })
}
