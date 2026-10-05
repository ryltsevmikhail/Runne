impl SqliteProviderExecutionStore {
    fn pending_terminal_outbox_impl(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.pending_terminal_outbox_for_attempt_impl(Option::<DispatchAttemptId>::None)
    }

    fn pending_terminal_outbox_for_attempt_impl(
        &self,
        attempt_id: impl Into<Option<DispatchAttemptId>>,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.pending_outbox_for_attempt_kind_impl(attempt_id, 1)
    }

    fn pending_tool_proposal_outbox_for_attempt_impl(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.pending_outbox_for_attempt_kind_impl(Some(attempt_id), 2)
    }

    fn pending_outbox_for_attempt_kind_impl(
        &self,
        attempt_id: impl Into<Option<DispatchAttemptId>>,
        application_kind: i64,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        let attempt_id = attempt_id.into().map(|id| id.as_bytes().to_vec());
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let orphaned: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_terminal_outbox outbox LEFT JOIN provider_terminal_application_kinds app ON app.dispatch_attempt_id=outbox.dispatch_attempt_id AND app.outbox_id=outbox.outbox_id WHERE outbox.state=1 AND (?1 IS NULL OR outbox.dispatch_attempt_id=?1) AND app.dispatch_attempt_id IS NULL)",
                rusqlite::params![attempt_id],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if orphaned {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        let mut statement = connection
            .prepare(
                "SELECT outbox.outbox_id, outbox.dispatch_attempt_id,
                        outbox.terminal_sequence, outbox.call_digest_version,
                        outbox.key_id, outbox.key_version, keys.runtime_authority_id,
                        keys.database_generation, outbox.nonce, outbox.runtime_generation,
                        outbox.profile_digest, outbox.ciphertext, outbox.plaintext_len,
                        outbox.plaintext_digest, outbox.settlement_digest,
                        outbox.application_idempotency_key, admission.principal_id,
                        admission.conversation_id, admission.taskrun_id,
                        admission.execution_attempt_id, admission.fencing_token,
                        remote.artifact_digest, unknown.unknown_commitment,
                        app.application_kind
                 FROM provider_terminal_outbox outbox
                 JOIN provider_journal_key_refs keys
                   ON keys.key_id = outbox.key_id AND keys.key_version = outbox.key_version
                 JOIN provider_execution_admissions admission
                   ON admission.dispatch_attempt_id = outbox.dispatch_attempt_id
                 JOIN provider_terminal_application_kinds app
                   ON app.dispatch_attempt_id=outbox.dispatch_attempt_id
                  AND app.outbox_id=outbox.outbox_id
                 LEFT JOIN provider_remote_terminal_settlements remote
                   ON remote.dispatch_attempt_id=outbox.dispatch_attempt_id
                  AND remote.source_kind=2 AND remote.terminal_status=1
                  AND remote.settlement_state IN (2,4)
                  AND remote.artifact_digest=outbox.plaintext_digest
                  AND remote.settlement_digest=outbox.settlement_digest
                 LEFT JOIN provider_unknown_terminal_receipts unknown
                   ON unknown.dispatch_attempt_id=outbox.dispatch_attempt_id
                  AND unknown.outbox_id=outbox.outbox_id
                 WHERE outbox.state = 1 AND (?1 IS NULL OR outbox.dispatch_attempt_id=?1)
                   AND app.application_kind=?2
                 ORDER BY outbox.created_at, outbox.outbox_id",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map(rusqlite::params![attempt_id, application_kind], |row| {
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(4)?)?,
                    positive_u64(row.get(5)?)?,
                    fixed_bytes(row.get(6)?)?,
                    positive_u64(row.get(7)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted_output = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(8)?)?,
                    row.get(11)?,
                    nonnegative_u64(row.get(12)?)?,
                    fixed_bytes(row.get(13)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let terminal_sequence = nonnegative_u64(row.get(2)?)?;
                let unknown_commitment = row.get::<_, Option<Vec<u8>>>(22)?;
                let source = if terminal_sequence == 0 {
                    if unknown_commitment.is_some() {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact {
                        artifact_digest: fixed_bytes(row.get(21)?)?,
                    }
                } else {
                    if row.get::<_, Option<Vec<u8>>>(21)?.is_some() {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    if let Some(commitment) = unknown_commitment {
                        let commitment: [u8; 32] = commitment
                            .as_slice()
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?;
                        if commitment != fixed_bytes(row.get(14)?)? {
                            return Err(rusqlite::Error::InvalidQuery);
                        }
                        runne_application::provider::ProviderTerminalOutboxSource::UnknownJournal {
                            commitment,
                        }
                    } else {
                        runne_application::provider::ProviderTerminalOutboxSource::StreamJournal
                    }
                };
                Ok(ProviderTerminalOutboxRecord {
                    application_kind: match row.get::<_, i64>(23)? {
                        1 => runne_application::provider::ProviderTerminalApplicationKind::TextGeneration,
                        2 => runne_application::provider::ProviderTerminalApplicationKind::ToolProposal,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    },
                    outbox_id: fixed_bytes(row.get(0)?)?,
                    attempt_id: DispatchAttemptId::from_bytes(fixed_bytes(row.get(1)?)?),
                    source,
                    fencing_token: positive_u64(row.get(20)?)?,
                    principal_id: row.get(16)?,
                    conversation_id: ConversationId::from_bytes(fixed_bytes(row.get(17)?)?),
                    taskrun_id: TaskRunId::from_bytes(fixed_bytes(row.get(18)?)?),
                    execution_attempt_id: AttemptId::from_bytes(fixed_bytes(row.get(19)?)?),
                    terminal_sequence,
                    call_digest_version: decode_call_digest_version(row.get(3)?)?,
                    key,
                    encrypted_output,
                    runtime_generation: positive_u64(row.get(9)?)?,
                    profile_digest: fixed_bytes(row.get(10)?)?,
                    settlement_digest: fixed_bytes(row.get(14)?)?,
                    application_idempotency_key: row.get(15)?,
                })
            })
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)
    }
}

include!("part_05_remote_artifact_ack.rs");
