pub fn snapshot(
    store: &mut LocalStore,
    secure: Option<&dyn gocode_secure_store::SecureStore>,
    scope: &ReplayScopeKey,
    reference: &StoredConversationReference,
) -> Result<ConversationSnapshot, AppCoreError> {
    let stored = match secure {
        Some(secure) => store.authenticated_conversation_projection(secure, scope),
        None => store.conversation_projection(scope),
    }
    .map_err(|error| map_store_error(&error))?
    .ok_or(AppCoreError::LocalProjectionUnavailable)?;
    if let Ok(snapshot) = generic_projection::conversation_snapshot(
        &stored.payload,
        stored.revision,
        stored.event_sequence,
        reference,
    ) {
        if digest(&stored.payload) == stored.digest && stored.binding_digest == scope.binding_digest
        {
            return Ok(snapshot);
        }
        return Err(AppCoreError::LocalProjectionUnavailable);
    }
    let projection: StoredConversationProjection = serde_json::from_slice(&stored.payload)
        .map_err(|_| AppCoreError::LocalProjectionUnavailable)?;
    if projection.schema_version != PROJECTION_SCHEMA_VERSION
        || projection.projection_revision != stored.revision
        || projection.stream_version != stored.event_sequence
        || digest(&stored.payload) != stored.digest
        || stored.binding_digest != scope.binding_digest
        || !valid_projection(&projection, reference)
    {
        return Err(AppCoreError::LocalProjectionUnavailable);
    }
    Ok(projection.snapshot())
}

pub fn checkpoint(
    store: &mut LocalStore,
    secure: Option<&dyn gocode_secure_store::SecureStore>,
    scope: &ReplayScopeKey,
) -> Result<Option<ReplayCheckpoint>, AppCoreError> {
    match secure {
        Some(secure) => store.authenticated_replay_checkpoint(secure, scope),
        None => store.replay_checkpoint(scope),
    }
    .map_err(|error| map_store_error(&error))
}

#[allow(clippy::too_many_lines)]
pub fn apply_delivery(
    store: &mut LocalStore,
    secure: Option<&dyn gocode_secure_store::SecureStore>,
    reference: &StoredConversationReference,
    identity: &StableRuntimeIdentity,
    delivery: &ReplayDelivery,
) -> Result<Option<ConversationTimelineUpdate>, AppCoreError> {
    let event = delivery.event();
    if event.aggregate_kind() != ReplayAggregateKind::Conversation
        || event.aggregate_id() != reference.conversation_id()
    {
        return Err(AppCoreError::RuntimeIdentityConflict);
    }
    let scope = identity.scope(reference);
    let checkpoint = match secure {
        Some(secure) => store.authenticated_replay_checkpoint(secure, &scope),
        None => store.replay_checkpoint(&scope),
    }
    .map_err(|error| map_store_error(&error))?;
    let stored_projection = match secure {
        Some(secure) => store.authenticated_conversation_projection(secure, &scope),
        None => store.conversation_projection(&scope),
    }
    .map_err(|error| map_store_error(&error))?;
    if checkpoint.is_some() != stored_projection.is_some() {
        return Err(AppCoreError::LocalProjectionUnavailable);
    }

    let mut projection = match stored_projection {
        Some(stored) => {
            let projection: StoredConversationProjection =
                match serde_json::from_slice(&stored.payload) {
                    Ok(projection) => projection,
                    Err(_) => generic_projection::legacy_projection(
                        &stored.payload,
                        stored.revision,
                        stored.event_sequence,
                        reference,
                    )?,
                };
            if projection.projection_revision != stored.revision
                || projection.stream_version != stored.event_sequence
                || !valid_projection(&projection, reference)
            {
                return Err(AppCoreError::LocalProjectionUnavailable);
            }
            projection
        }
        None => StoredConversationProjection::empty(reference),
    };

    let duplicate = checkpoint
        .as_ref()
        .is_some_and(|current| current.event_sequence == event.sequence());
    if checkpoint
        .as_ref()
        .is_some_and(|current| event.sequence() < current.event_sequence)
    {
        let confirmed = delivery.persist_with(|handoff| {
            let applied = AppliedReplayEvent {
                scope: &scope,
                event_id: &event.event_id().to_string(),
                cursor: handoff.cursor_value(),
                generation: identity.launch_generation,
                event_sequence: event.sequence(),
                event_bytes: handoff.canonical_event_bytes(),
                event_digest: handoff.event_digest(),
            };
            match secure {
                Some(secure) => store.authenticated_confirm_replay_event_applied(secure, &applied),
                None => store.confirm_replay_event_applied(&applied),
            }
        });
        return match confirmed.map_err(|error| map_store_error(&error))? {
            ReplayApplyOutcome::AlreadyApplied { .. } => Ok(None),
            ReplayApplyOutcome::Applied { .. } => Err(AppCoreError::RuntimeIdentityConflict),
        };
    }
    let message = if duplicate {
        None
    } else {
        reduce(&mut projection, reference, delivery)?
    };
    let projection_bytes =
        serde_json::to_vec(&projection).map_err(|_| AppCoreError::LocalProjectionUnavailable)?;
    let projection_digest = digest(&projection_bytes);
    let event_id = event.event_id().to_string();
    let generation = if duplicate {
        checkpoint
            .as_ref()
            .map_or(identity.launch_generation, |value| value.generation)
    } else {
        identity.launch_generation
    };
    let outcome = delivery.persist_with(|handoff| {
        let transition = ReplayTransition {
            scope: &scope,
            expected_checkpoint: checkpoint.as_ref(),
            event_id: &event_id,
            cursor: handoff.cursor_value(),
            generation,
            event_sequence: event.sequence(),
            event_bytes: handoff.canonical_event_bytes(),
            event_digest: handoff.event_digest().to_owned(),
            projection_revision: projection.projection_revision,
            projection_bytes: &projection_bytes,
            projection_digest,
        };
        match secure {
            Some(secure) => store.apply_anchored_replay_transition(secure, &transition),
            None => store.apply_replay_transition(&transition),
        }
    });
    match outcome.map_err(|error| map_store_error(&error))? {
        ReplayApplyOutcome::AlreadyApplied { .. } => Ok(None),
        ReplayApplyOutcome::Applied { .. } => Ok(Some(ConversationTimelineUpdate {
            conversation_id: projection.conversation_id,
            projection_revision: projection.projection_revision,
            stream_version: projection.stream_version,
            message,
            recovery: ConversationRecoveryDisposition::Live,
        })),
    }
}

fn reduce(
    projection: &mut StoredConversationProjection,
    reference: &StoredConversationReference,
    delivery: &ReplayDelivery,
) -> Result<Option<ConversationMessageSummary>, AppCoreError> {
    let event = delivery.event();
    if projection
        .stream_version
        .checked_add(1)
        .is_none_or(|next| next != event.sequence())
        || projection.closed
    {
        return Err(AppCoreError::RuntimeIdentityConflict);
    }
    let payload = match event.payload() {
        CanonicalReplayPayload::Conversation(payload) => payload,
        CanonicalReplayPayload::TaskRun(_) => return Err(AppCoreError::RuntimeIdentityConflict),
    };
    let message = match payload {
        ConversationReplayPayload::Created { workspace_id } => {
            if event.sequence() != 1
                || *workspace_id != reference.workspace_id()
                || projection.stream_version != 0
            {
                return Err(AppCoreError::RuntimeIdentityConflict);
            }
            None
        }
        ConversationReplayPayload::MessageAppended {
            role,
            message_id,
            task_run_id,
            attempt_id,
            text,
        } => {
            if projection
                .messages
                .iter()
                .any(|message| message.message_id == message_id.to_string())
            {
                return Err(AppCoreError::RuntimeIdentityConflict);
            }
            let committed_at = u64::try_from(event.timestamp_unix_micros())
                .map_err(|_| AppCoreError::RuntimeIdentityConflict)?;
            let message = ConversationMessageSummary {
                message_id: message_id.to_string(),
                role: match role {
                    ConversationMessageRole::User => "user",
                    ConversationMessageRole::Assistant => "assistant",
                }
                .to_owned(),
                task_run_id: task_run_id.to_string(),
                attempt_id: attempt_id.to_string(),
                text: text.clone(),
                committed_at,
            };
            projection.messages.push(message.clone());
            Some(message)
        }
        ConversationReplayPayload::GenerationFailed { .. } => None,
        ConversationReplayPayload::Closed => {
            projection.closed = true;
            None
        }
    };
    projection.stream_version = event.sequence();
    projection.projection_revision = projection
        .projection_revision
        .checked_add(1)
        .ok_or(AppCoreError::LocalProjectionUnavailable)?;
    Ok(message)
}
