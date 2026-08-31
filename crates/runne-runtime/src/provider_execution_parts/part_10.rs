impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Encrypts and commits one normalized event, rebinding only to a forward key rotation.
    fn commit_polled_event(
        &self,
        context: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<(ProviderJournalAppendOutcome, ProviderStreamItem), RuntimeProviderExecutionError>
    {
        let event = match self
            .redaction
            .scan_before_journal(context, event)
            .map_err(|_| RuntimeProviderExecutionError::PolicyDenied)?
        {
            PreJournalProviderEvent::Append(event) => event,
            PreJournalProviderEvent::Terminal(_) => {
                return Err(RuntimeProviderExecutionError::PolicyDenied);
            }
        };
        if event.sequence() == u64::MAX {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let sanitized_item = ProviderStreamItem::from_event(event.clone())
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
        let event_kind = event_kind_code(event.kind());
        let terminal = matches!(
            event.kind(),
            ProviderStreamEventKind::Finished { .. }
                | ProviderStreamEventKind::ScannerCompleted { .. }
        );
        let plaintext = serde_json::to_vec(&event)
            .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
        let mut key = self.current_key()?;
        loop {
            let request = self.sealed_event_request(
                context,
                event.sequence(),
                event_kind,
                terminal,
                &plaintext,
                key,
            )?;
            match self.store.append_encrypted_event(&request) {
                Ok(outcome) => return Ok((outcome, sanitized_item)),
                Err(ProviderExecutionError::JournalKeyUnavailable) => {
                    key = self.rebind_forward_active_key(key)?;
                }
                Err(error) => return Err(map_execution_error(error)),
            }
        }
    }

    fn sealed_event_request(
        &self,
        context: &ProviderEventJournalContext,
        sequence: u64,
        event_kind: u8,
        terminal: bool,
        plaintext: &[u8],
        key: ProviderJournalKeyBinding,
    ) -> Result<ProviderJournalAppendRequest, RuntimeProviderExecutionError> {
        let material = self.load_key(key)?;
        let aad = event_aad(context, key, sequence, event_kind, terminal);
        let encrypted = self.seal(&material, &aad, plaintext)?;
        Ok(ProviderJournalAppendRequest {
            attempt_id: context.attempt_id,
            fencing_token: context.fencing_token,
            sequence,
            event_kind,
            terminal,
            call_digest_version: context.call_digest_version,
            profile_digest: context.profile_digest,
            runtime_generation: context.runtime_generation,
            key,
            encrypted,
        })
    }
}
