async fn list_conversations_page<E: ConversationRepository + Send + 'static>(
    store: E,
    principal: runne_api::ApiPrincipalId,
    workspace: runne_domain::id::WorkspaceId,
    limit: u16,
    after: Option<runne_domain::id::ConversationId>,
) -> Result<runne_api::ConversationListPage, ConversationHostError> {
    if !(1..=100).contains(&limit) {
        return Err(ConversationHostError::InvariantViolation);
    }
    tokio::task::spawn_blocking(move || {
        let streams = store
            .list_conversations(
                &PrincipalId(principal.as_str().to_owned()),
                workspace,
                limit + 1,
                after,
            )
            .map_err(map_event_store_error)?;
        let has_more = streams.len() > usize::from(limit);
        let mut items = Vec::new();
        for (id, stream) in streams.into_iter().take(usize::from(limit)) {
            validate_loaded_stream(&stream)?;
            Conversation::replay(&stream.events).map_err(|_| ConversationHostError::Unavailable)?;
            let title = stream
                .events
                .iter()
                .find_map(|event| match event.payload() {
                    ConversationEvent::UserMessageAppended { text, .. } => Some(
                        text.as_str()
                            .lines()
                            .next()
                            .unwrap_or("Session")
                            .chars()
                            .take(80)
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_else(|| "New session".into());
            let updated = stream
                .events
                .last()
                .ok_or(ConversationHostError::InvariantViolation)?
                .timestamp()
                .as_unix_micros()
                .div_euclid(1_000);
            items.push(runne_api::ConversationListItem {
                conversation_id: id,
                workspace_id: workspace,
                stream_version: stream.current_version,
                title,
                updated_at: NonNegativeUnixMillis::new(updated)
                    .ok_or(ConversationHostError::InvariantViolation)?,
            });
        }
        let next_after = has_more
            .then(|| items.last().map(|item| item.conversation_id))
            .flatten();
        Ok(runne_api::ConversationListPage { items, next_after })
    })
    .await
    .map_err(|_| ConversationHostError::Unavailable)?
}
