fn lookup_durable_receipt<R: ConversationTextRepository>(
    repository: &R,
    context: &ApplicationCommandContext,
    scope: &IdempotencyScope,
    original: &BeginConversationTextInput,
) -> Result<(CommandFingerprint, TextGenerationReceipt), ConversationTextServiceError> {
    let fingerprint = CommandFingerprint::for_generate_conversation_text(
        &original.conversation_id,
        original.expected_version,
        &original.text,
    );
    let receipt = match repository
        .lookup_text_generation_receipt(
            context.command_id,
            &context.idempotency_key,
            scope,
            &fingerprint,
        )
        .map_err(map_commit)?
    {
        TextGenerationReceiptLookup::Miss => {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        TextGenerationReceiptLookup::Duplicate { stored_result } => stored_result,
    };
    Ok((fingerprint, receipt))
}
