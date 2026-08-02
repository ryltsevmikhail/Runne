fn digest(bytes: &[u8]) -> String {
    replay_persistence_digest(bytes)
}

fn valid_projection(
    projection: &StoredConversationProjection,
    reference: &StoredConversationReference,
) -> bool {
    if projection.schema_version != PROJECTION_SCHEMA_VERSION
        || projection.conversation_id != reference.conversation_id().to_string()
        || projection.workspace_id != reference.workspace_id().to_string()
        || projection.messages.len()
            > usize::try_from(projection.projection_revision).unwrap_or(usize::MAX)
    {
        return false;
    }
    let mut message_ids = std::collections::HashSet::with_capacity(projection.messages.len());
    projection.messages.iter().all(|message| {
        matches!(message.role.as_str(), "user" | "assistant")
            && message.text.len() <= 64 * 1024
            && CanonicalId::parse(&message.message_id).is_ok()
            && CanonicalId::parse(&message.task_run_id).is_ok()
            && CanonicalId::parse(&message.attempt_id).is_ok()
            && message_ids.insert(&message.message_id)
    })
}

const fn map_store_error(error: &ReplayStoreError) -> AppCoreError {
    match error {
        ReplayStoreError::BindingMismatch | ReplayStoreError::EventIdentityConflict => {
            AppCoreError::RuntimeIdentityConflict
        }
        ReplayStoreError::InvalidScope
        | ReplayStoreError::InvalidDigest
        | ReplayStoreError::EmptyCursor
        | ReplayStoreError::CorruptProjectionJson
        | ReplayStoreError::EventDigestMismatch
        | ReplayStoreError::ProjectionDigestMismatch
        | ReplayStoreError::CursorMismatch
        | ReplayStoreError::GenerationMismatch
        | ReplayStoreError::NonContiguousSequence
        | ReplayStoreError::NonContiguousRevision
        | ReplayStoreError::IntegerOutOfRange
        | ReplayStoreError::Storage(_) => AppCoreError::LocalProjectionUnavailable,
    }
}
