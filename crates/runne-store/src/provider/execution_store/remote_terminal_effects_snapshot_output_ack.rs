fn remote_output_acknowledged(
    transaction: &Transaction<'_>,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
    fact: Option<&runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
) -> Result<Option<RemoteOutputAckProjection>, ProviderExecutionError> {
    let Some(terminal) = record.terminal.as_ref() else {
        return Ok(None);
    };
    let binding = &record.request.binding;
    let dispatch = binding.dispatch_attempt_id.as_bytes();
    let any_acknowledged: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_settlements s
             JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
             WHERE s.dispatch_attempt_id=?1 AND s.source_kind=2 AND s.settlement_state=4
               AND o.terminal_sequence=0 AND o.state=2)",
            [dispatch.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !any_acknowledged {
        return Ok(None);
    }
    let acknowledged: (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) = transaction
        .query_row(
            "SELECT o.outbox_id,s.settlement_digest,o.receipt_digest,s.published_output_digest
             FROM provider_remote_terminal_settlements s
             JOIN provider_remote_terminal_artifacts t USING(dispatch_attempt_id)
             JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
             JOIN provider_terminal_dispositions p USING(dispatch_attempt_id)
             JOIN provider_accounting_settlements f USING(dispatch_attempt_id)
             WHERE s.dispatch_attempt_id=?1 AND s.source_kind=2
               AND s.taskrun_id=?2 AND s.taskrun_attempt_id=?3
               AND s.request_digest=?4 AND s.response_id_digest=?5
               AND s.artifact_digest=?6 AND s.terminal_status=?7
               AND s.settlement_state=4 AND s.application_receipt_digest=o.receipt_digest
               AND s.publication_disposition=0
               AND t.plaintext_digest=s.artifact_digest AND t.disposition=s.terminal_status
               AND p.disposition=1 AND o.state=2 AND o.receipt_digest IS NOT NULL
               AND o.applied_at IS NOT NULL AND o.plaintext_digest=s.artifact_digest
               AND o.settlement_digest=f.settlement_digest
               AND f.pricing_revision_digest=s.pricing_revision_digest
               AND f.input_tokens IS s.input_tokens AND f.output_tokens IS s.output_tokens
               AND f.cached_input_tokens IS s.cached_input_tokens
               AND f.reasoning_output_tokens IS s.reasoning_output_tokens
               AND f.charge_micros IS s.charge_micros AND f.currency IS s.currency
               AND f.settlement_digest IS s.settlement_digest",
            params![
                dispatch.as_slice(),
                binding.taskrun_id.as_bytes().as_slice(),
                binding.taskrun_attempt_id.as_bytes().as_slice(),
                binding.request_digest.as_slice(),
                terminal.response_id_digest.as_slice(),
                terminal.encrypted_artifact.plaintext_digest().as_slice(),
                terminal.disposition.code(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let outbox_id: [u8; 16] = acknowledged
        .0
        .as_slice()
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let settlement_digest: [u8; 32] = acknowledged
        .1
        .as_slice()
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let receipt_digest: [u8; 32] = acknowledged
        .2
        .as_slice()
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some(ack_kind) = validate_remote_artifact_ack(
        transaction,
        outbox_id,
        *dispatch,
        settlement_digest,
        receipt_digest,
        4,
    )?
    else {
        return Err(ProviderExecutionError::JournalCorrupt);
    };
    Ok(Some(match ack_kind {
        RemoteArtifactAckKind::AuditOnly => RemoteOutputAckProjection::AuditOnly,
        RemoteArtifactAckKind::PublishedOutput => match fact {
            None => RemoteOutputAckProjection::Unverified,
            Some(fact)
                if fact.publication_disposition()
                    == runne_provider::ProviderRemotePublicationDisposition::Allowed
                    && matches!(
                        fact.status(),
                        runne_provider::ProviderRemoteResponseStatus::Completed { .. }
                    )
                    && fact.output_digest().is_some_and(|digest| {
                        acknowledged.3.as_deref() == Some(digest.as_slice())
                    }) =>
            {
                RemoteOutputAckProjection::PublishedOutput
            }
            Some(_) => return Err(ProviderExecutionError::JournalCorrupt),
        },
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteOutputAckProjection {
    PublishedOutput,
    AuditOnly,
    Unverified,
}
