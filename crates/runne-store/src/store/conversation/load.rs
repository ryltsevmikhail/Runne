use super::super::*;
mod connection;
pub(crate) use connection::load_conversation_from_connection;

impl StoreTransaction {
    pub(super) fn load_conversation_impl(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationLoadedStream, EventStoreError> {
        let conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        load_conversation_from_connection(&conn, conversation_id)
    }
}
