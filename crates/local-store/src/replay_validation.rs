fn validate_replay_scope(scope: &ReplayScopeKey) -> Result<(), ReplayStoreError> {
    if scope.runtime_authority.is_empty()
        || scope.principal.is_empty()
        || scope.lineage.is_empty()
        || scope.scope.is_empty()
    {
        return Err(ReplayStoreError::InvalidScope);
    }
    if !is_lower_hex_digest(&scope.binding_digest) {
        return Err(ReplayStoreError::InvalidDigest);
    }
    Ok(())
}

fn validate_replay_transition_shape(
    transition: &ReplayTransition<'_>,
) -> Result<(), ReplayStoreError> {
    validate_replay_scope(transition.scope)?;
    if transition.event_id.is_empty() {
        return Err(ReplayStoreError::InvalidScope);
    }
    if transition.cursor.is_empty() {
        return Err(ReplayStoreError::EmptyCursor);
    }
    if transition.event_sequence == 0 {
        return Err(ReplayStoreError::NonContiguousSequence);
    }
    Ok(())
}

fn validate_replay_transition_payload(
    connection: &Connection,
    transition: &ReplayTransition<'_>,
) -> Result<(), ReplayStoreError> {
    if !is_lower_hex_digest(&transition.event_digest)
        || !is_lower_hex_digest(&transition.projection_digest)
    {
        return Err(ReplayStoreError::InvalidDigest);
    }
    if sha256_lower_hex(transition.event_bytes) != transition.event_digest {
        return Err(ReplayStoreError::EventDigestMismatch);
    }
    if sha256_lower_hex(transition.projection_bytes) != transition.projection_digest {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }
    let valid_json: i64 = connection.query_row(
        "SELECT json_valid(?1)",
        params![transition.projection_bytes],
        |row| row.get(0),
    )?;
    if valid_json != 1 {
        return Err(ReplayStoreError::CorruptProjectionJson);
    }
    Ok(())
}

fn validate_expected_transition(
    current: Option<&VerifiedReplayState>,
    transition: &ReplayTransition<'_>,
) -> Result<(), ReplayStoreError> {
    match (current, transition.expected_checkpoint) {
        (None, None) => {
            if transition.event_sequence != 1 {
                return Err(ReplayStoreError::NonContiguousSequence);
            }
            if transition.projection_revision > 1 {
                return Err(ReplayStoreError::NonContiguousRevision);
            }
        }
        (None, Some(_)) | (Some(_), None) => return Err(ReplayStoreError::CursorMismatch),
        (Some(current), Some(expected)) => {
            let checkpoint = &current.checkpoint;
            if expected.binding_digest != transition.scope.binding_digest
                || expected.binding_digest != checkpoint.binding_digest
            {
                return Err(ReplayStoreError::BindingMismatch);
            }
            if expected.cursor != checkpoint.cursor {
                return Err(ReplayStoreError::CursorMismatch);
            }
            if expected.generation != checkpoint.generation {
                return Err(ReplayStoreError::GenerationMismatch);
            }
            if expected.event_sequence != checkpoint.event_sequence {
                return Err(ReplayStoreError::NonContiguousSequence);
            }
            if expected.projection_revision != checkpoint.projection_revision {
                return Err(ReplayStoreError::NonContiguousRevision);
            }
            if expected.projection_digest != checkpoint.projection_digest {
                return Err(ReplayStoreError::ProjectionDigestMismatch);
            }
            if transition.cursor == checkpoint.cursor {
                return Err(ReplayStoreError::CursorMismatch);
            }
            if transition.generation < checkpoint.generation {
                return Err(ReplayStoreError::GenerationMismatch);
            }
            if checkpoint.event_sequence.checked_add(1) != Some(transition.event_sequence) {
                return Err(ReplayStoreError::NonContiguousSequence);
            }
            if transition.projection_revision == checkpoint.projection_revision {
                if transition.projection_digest != current.projection.digest
                    || transition.projection_bytes != current.projection.payload
                {
                    return Err(ReplayStoreError::NonContiguousRevision);
                }
            } else if checkpoint.projection_revision.checked_add(1)
                != Some(transition.projection_revision)
            {
                return Err(ReplayStoreError::NonContiguousRevision);
            }
        }
    }
    Ok(())
}
