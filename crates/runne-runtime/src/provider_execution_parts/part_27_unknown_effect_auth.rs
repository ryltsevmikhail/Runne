impl<K, S> runne_application::provider::ProviderUnknownTerminalFactAuthenticator
    for RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized,
{
    fn authenticate_unknown_terminal(
        &self,
        snapshot: &ProviderUnknownTerminalSnapshot,
    ) -> Result<runne_application::provider::ProviderUnknownTerminalFact, ProviderExecutionError>
    {
        self.store
            .verify_unknown_original_effect(snapshot.original_effect())?;
        let mut keys = Vec::new();
        for record in snapshot.journal() {
            if keys.iter().any(|(binding, _)| *binding == record.key) {
                continue;
            }
            let key_ref = secure_ref_from_binding(record.key)
                .map_err(|_| ProviderExecutionError::JournalKeyUnavailable)?;
            let material = self
                .keyring
                .load_provider_journal_key(key_ref)
                .map_err(|_| ProviderExecutionError::JournalKeyUnavailable)?;
            keys.push((record.key, material));
        }
        let events = decrypt_unknown_snapshot(snapshot.journal(), &keys)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        let assembled = assemble_terminal_stream(&events)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        let selector = snapshot.selector();
        let context = snapshot.context();
        let current = snapshot.current();
        let authenticator = RuntimeUnknownAuthenticator {
            selector,
            context,
            journal_digest: journal_records_digest(snapshot.journal()),
            keys: &keys,
            reason: None,
            disposition: assembled.disposition,
            usage: assembled.usage.exact(),
            output: None,
            outbox_id: stable_outbox_id(&context, selector.terminal_sequence()),
        };
        let authorization = authenticator.authenticate(snapshot)?;
        Ok(runne_application::provider::ProviderUnknownTerminalFact {
            disposition: authorization.disposition(),
            usage: authorization.usage(),
            output_digest: authorization
                .encrypted_output()
                .map(|output| *output.plaintext_digest()),
            output_was_published: authorization.published_outbox_id().is_some(),
            output_was_applied: current.existing_application_ack_digest.is_some(),
        })
    }
}
