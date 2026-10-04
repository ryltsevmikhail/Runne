impl<R, I> ConversationTextCommandService for ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn begin_text(
        &self,
        context: &ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.begin(context, input)
    }

    fn begin_claimed_text(
        &self,
        context: &ApplicationCommandContext,
        input: crate::commands::BeginClaimedConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.begin_claimed(context, input)
    }

    fn finish_text(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.finish(context, input)
    }
}
