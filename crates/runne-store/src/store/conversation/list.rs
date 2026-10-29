use super::super::*;
use super::load_conversation_from_connection;
use runne_application::ports::PrincipalId;
use runne_domain::id::WorkspaceId;

impl StoreTransaction {
    pub(super) fn list_conversations_impl(
        &self,
        principal: &PrincipalId,
        workspace: WorkspaceId,
        limit: u16,
        after: Option<ConversationId>,
    ) -> Result<Vec<(ConversationId, ConversationLoadedStream)>, EventStoreError> {
        if !(1..=101).contains(&limit) {
            return Err(EventStoreError::Unavailable);
        }
        // Match the existing durable create receipt's exact encoded scope; do not
        // infer ownership from the event actor or from the presence of a TaskRun.
        let scope = IdempotencyScope {
            runtime_authority_id: self.runtime_authority_id.clone(),
            principal_id: principal.clone(),
            operation: OperationTag::CreateConversation,
            aggregate_scope: AggregateScope::NewConversation {
                conversation_id: ConversationId::from_bytes([0; 16]),
                workspace_id: workspace,
            },
        };
        let mut prefix = IdempotencyScopeCodec
            .encode(&scope)
            .map_err(|_| EventStoreError::CorruptData)?;
        prefix.truncate(
            prefix
                .len()
                .checked_sub(32)
                .ok_or(EventStoreError::CorruptData)?,
        );
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let mut statement = connection.prepare("SELECT e.aggregate_id,r.idempotency_scope_bytes FROM events e JOIN command_receipts r ON r.command_id=e.command_id WHERE e.aggregate_type=2 AND e.sequence=1 AND e.aggregate_id>?1 AND length(r.idempotency_scope_bytes)=?2 AND substr(r.idempotency_scope_bytes,1,?3)=?4 AND substr(r.idempotency_scope_bytes,-16)=?5 ORDER BY e.aggregate_id LIMIT ?6").map_err(|_| EventStoreError::CorruptData)?;
        let floor = after.map_or([0; 16], |id| *id.as_bytes());
        let rows = statement
            .query_map(
                params![
                    floor.as_slice(),
                    prefix.len() + 32,
                    prefix.len(),
                    prefix,
                    workspace.as_bytes(),
                    limit
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let mut result = Vec::new();
        for row in rows {
            let (id, scope) = row.map_err(|_| EventStoreError::CorruptData)?;
            let id = ConversationId::from_bytes(
                id.try_into().map_err(|_| EventStoreError::CorruptData)?,
            );
            let scope = IdempotencyScopeCodec
                .decode(&scope)
                .map_err(|_| EventStoreError::CorruptData)?;
            if scope.runtime_authority_id != self.runtime_authority_id
                || &scope.principal_id != principal
                || scope.operation != OperationTag::CreateConversation
                || scope.aggregate_scope
                    != (AggregateScope::NewConversation {
                        conversation_id: id,
                        workspace_id: workspace,
                    })
            {
                return Err(EventStoreError::CorruptData);
            }
            let stream = load_conversation_from_connection(&connection, id)?;
            if !matches!(stream.events.first().map(|event| event.payload()), Some(ConversationEvent::ConversationCreated { workspace_id }) if *workspace_id == workspace)
            {
                return Err(EventStoreError::CorruptData);
            }
            result.push((id, stream));
        }
        Ok(result)
    }
}
