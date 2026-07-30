use gocode_local_store::{
    AppliedReplayEvent, LocalStore, ReplayApplyOutcome, ReplayCheckpoint, ReplayScopeKey,
    ReplayStoreError, ReplayTransition,
};
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CanonicalReplayPayload, ConversationMessageRole,
    ConversationReplayPayload, ReplayAggregateKind, ReplayDelivery, replay_persistence_digest,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppCoreError, ConversationMessageSummary, ConversationRecoveryDisposition,
    ConversationSnapshot, ConversationTimelineUpdate, StoredConversationReference,
    StoredConversationReferenceV2,
};

const PROJECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableRuntimeIdentity {
    pub authority: String,
    pub principal: String,
    pub lineage: String,
    pub profile_id: String,
    pub schema_hash: String,
    pub capability_digest: String,
    pub binding_digest: String,
    pub launch_generation: u64,
}

impl StableRuntimeIdentity {
    pub fn from_client(client: &AuthenticatedRuntimeClient) -> Self {
        let session = client.session_info();
        Self {
            authority: session.authority_id.clone(),
            principal: session.principal_id.clone(),
            lineage: session.event_log_lineage_id.clone(),
            profile_id: session.profile_id.clone(),
            schema_hash: session.schema_hash.clone(),
            capability_digest: session.capability_digest.clone(),
            binding_digest: client.replay_persistence_binding().digest().to_owned(),
            launch_generation: session.launch_generation,
        }
    }

    pub fn matches_reference(&self, reference: &StoredConversationReferenceV2) -> bool {
        [
            self.authority == reference.runtime_authority,
            self.principal == reference.principal,
            self.lineage == reference.lineage,
            self.profile_id == reference.profile_id,
            self.schema_hash == reference.schema_hash,
            self.capability_digest == reference.capability_digest,
        ]
        .into_iter()
        .all(std::convert::identity)
    }

    pub fn bind_reference(
        &self,
        reference: &StoredConversationReference,
    ) -> StoredConversationReferenceV2 {
        StoredConversationReferenceV2 {
            schema_version: 2,
            conversation_id: reference.conversation_id(),
            workspace_id: reference.workspace_id(),
            create_command_id: reference.create_command_id(),
            idempotency_key: reference.idempotency_key().to_owned(),
            runtime_authority: self.authority.clone(),
            principal: self.principal.clone(),
            lineage: self.lineage.clone(),
            profile_id: self.profile_id.clone(),
            schema_hash: self.schema_hash.clone(),
            capability_digest: self.capability_digest.clone(),
        }
    }

    pub fn scope(&self, reference: &StoredConversationReference) -> ReplayScopeKey {
        ReplayScopeKey {
            runtime_authority: self.authority.clone(),
            principal: self.principal.clone(),
            lineage: self.lineage.clone(),
            scope: format!("conversation:{}", reference.conversation_id()),
            binding_digest: self.binding_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConversationProjection {
    schema_version: u32,
    conversation_id: String,
    workspace_id: String,
    projection_revision: u64,
    stream_version: u64,
    messages: Vec<ConversationMessageSummary>,
    closed: bool,
}

impl StoredConversationProjection {
    fn empty(reference: &StoredConversationReference) -> Self {
        Self {
            schema_version: PROJECTION_SCHEMA_VERSION,
            conversation_id: reference.conversation_id().to_string(),
            workspace_id: reference.workspace_id().to_string(),
            projection_revision: 0,
            stream_version: 0,
            messages: Vec::new(),
            closed: false,
        }
    }

    fn snapshot(self) -> ConversationSnapshot {
        ConversationSnapshot {
            conversation_id: self.conversation_id,
            projection_revision: self.projection_revision,
            stream_version: self.stream_version,
            messages: self.messages,
            recovery: ConversationRecoveryDisposition::Live,
        }
    }
}

pub fn snapshot(
    store: &LocalStore,
    scope: &ReplayScopeKey,
    reference: &StoredConversationReference,
) -> Result<ConversationSnapshot, AppCoreError> {
    let stored = store
        .conversation_projection(scope)
        .map_err(|error| map_store_error(&error))?
        .ok_or(AppCoreError::LocalProjectionUnavailable)?;
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
    store: &LocalStore,
    scope: &ReplayScopeKey,
) -> Result<Option<ReplayCheckpoint>, AppCoreError> {
    store
        .replay_checkpoint(scope)
        .map_err(|error| map_store_error(&error))
}

pub fn apply_delivery(
    store: &mut LocalStore,
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
    let checkpoint = store
        .replay_checkpoint(&scope)
        .map_err(|error| map_store_error(&error))?;
    let stored_projection = store
        .conversation_projection(&scope)
        .map_err(|error| map_store_error(&error))?;
    if checkpoint.is_some() != stored_projection.is_some() {
        return Err(AppCoreError::LocalProjectionUnavailable);
    }

    let mut projection = match stored_projection {
        Some(stored) => {
            let projection: StoredConversationProjection = serde_json::from_slice(&stored.payload)
                .map_err(|_| AppCoreError::LocalProjectionUnavailable)?;
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
            store.confirm_replay_event_applied(&AppliedReplayEvent {
                scope: &scope,
                event_id: &event.event_id().to_string(),
                cursor: handoff.cursor_value(),
                generation: identity.launch_generation,
                event_sequence: event.sequence(),
                event_bytes: handoff.canonical_event_bytes(),
                event_digest: handoff.event_digest(),
            })
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
        store.apply_replay_transition(&ReplayTransition {
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
        })
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
