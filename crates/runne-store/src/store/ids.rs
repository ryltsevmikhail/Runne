use super::*;

impl IdGenerator for StoreTransaction {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok(TaskRunId::from_bytes(self.generate_uuid()))
    }

    fn next_conversation_id(&self) -> Result<runne_domain::id::ConversationId, IdGenerationError> {
        Ok(runne_domain::id::ConversationId::from_bytes(
            self.generate_uuid(),
        ))
    }

    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(AttemptId::from_bytes(self.generate_uuid()))
    }

    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        Ok(MessageId::from_bytes(self.generate_uuid()))
    }

    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        if count == 0 {
            return Err(IdGenerationError::Exhausted);
        }
        let ids: Vec<EventId> = (0..count)
            .map(|_| EventId::from_bytes(self.generate_uuid()))
            .collect();
        Ok(ids)
    }
}
