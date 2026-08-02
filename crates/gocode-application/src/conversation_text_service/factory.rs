impl<R, I> ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore,
    I: IdGenerator,
{
    /// Creates a coordinator from abstract persistence and identity ports.
    pub fn new(
        repository: R,
        id_generator: I,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Self {
        Self {
            repository,
            id_generator,
            runtime_authority_id,
            prohibited_content,
        }
    }
}
