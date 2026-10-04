fn map_conversation_terminal_error(
    error: ConversationTextServiceError,
) -> ProviderTerminalApplicationError {
    match error {
        ConversationTextServiceError::StoredDataUnavailable
        | ConversationTextServiceError::Commit(_) => ProviderTerminalApplicationError::Unavailable,
        ConversationTextServiceError::ProhibitedSecretMaterial
        | ConversationTextServiceError::ConversationNotFound
        | ConversationTextServiceError::Conflict
        | ConversationTextServiceError::WriterFenced
        | ConversationTextServiceError::ConversationDomain(_)
        | ConversationTextServiceError::TaskRunDomain
        | ConversationTextServiceError::IdGeneration(_)
        | ConversationTextServiceError::MaterializationFailed
        | ConversationTextServiceError::ReceiptMismatch => {
            ProviderTerminalApplicationError::Conflict
        }
    }
}

fn conversation_receipt_digest(
    record: &ProviderTerminalOutboxRecord,
    receipt: &TextGenerationReceipt,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let runne_application::provider::ProviderTerminalOutboxSource::UnknownJournal {
        commitment,
    } = record.source
    {
        hasher.update(b"GOCODE_PROVIDER_UNKNOWN_CONVERSATION_RECEIPT_V1\0");
        hasher.update(commitment);
        hasher.update(record.outbox_id);
    } else {
        // Keep V1 Known and remote-compatible receipt bytes unchanged.
        hasher.update(b"GOCODE_PROVIDER_CONVERSATION_RECEIPT_V1\0");
        hasher.update(record.outbox_id);
        hasher.update(record.settlement_digest);
    }
    hasher.update(receipt.conversation_id.as_bytes());
    hasher.update(receipt.taskrun_id.as_bytes());
    hasher.update(receipt.attempt_id.as_bytes());
    hasher.update(receipt.user_message_id.as_bytes());
    hasher.update(receipt.assistant_message_id.as_bytes());
    hasher.update(receipt.conversation_version.to_be_bytes());
    hasher.update(receipt.taskrun_version.to_be_bytes());
    hasher.finalize().into()
}

fn remote_artifact_audit_receipt_digest(record: &ProviderTerminalOutboxRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_PROVIDER_REMOTE_ARTIFACT_AUDIT_ACK_V1\0");
    hasher.update(record.outbox_id);
    hasher.update(record.settlement_digest);
    hasher.update(record.taskrun_id.as_bytes());
    hasher.update(record.execution_attempt_id.as_bytes());
    if let runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact {
        artifact_digest,
    } = &record.source
    {
        hasher.update(artifact_digest);
    }
    hasher.finalize().into()
}

fn unknown_journal_audit_receipt_digest(record: &ProviderTerminalOutboxRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_PROVIDER_UNKNOWN_JOURNAL_AUDIT_ACK_V1\0");
    hasher.update(record.outbox_id);
    if let runne_application::provider::ProviderTerminalOutboxSource::UnknownJournal {
        commitment,
    } = record.source
    {
        hasher.update(commitment);
    }
    hasher.update(record.taskrun_id.as_bytes());
    hasher.update(record.execution_attempt_id.as_bytes());
    hasher.finalize().into()
}
