use super::{
    AppCoreError, LocalStore, ReplayApplyOutcome, ReplayCheckpoint, ReplayScopeKey,
    ReplayTransition, StableRuntimeIdentity, map_store_error, replay_persistence_digest,
};
use crate::{TaskRunTimelineEntry, TaskRunTimelineUpdate};
use runne_runtime_client::{CanonicalReplayPayload, ReplayAggregateKind, ReplayDelivery};
use serde::{Deserialize, Serialize};

const TASK_RUN_PROJECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredTaskRunProjection {
    schema_version: u32,
    task_run_id: String,
    pub projection_revision: u64,
    pub stream_version: u64,
    pub entries: Vec<TaskRunTimelineEntry>,
}

pub enum TaskRunProjection {
    Missing,
    Decoded(StoredTaskRunProjection),
    AuthenticatedOpaque { revision: u64, stream_version: u64 },
}

impl StoredTaskRunProjection {
    fn empty(task_run_id: &str) -> Self {
        Self {
            schema_version: TASK_RUN_PROJECTION_SCHEMA_VERSION,
            task_run_id: task_run_id.to_owned(),
            projection_revision: 0,
            stream_version: 0,
            entries: Vec::new(),
        }
    }

    fn valid(&self, task_run_id: &str) -> bool {
        self.schema_version == TASK_RUN_PROJECTION_SCHEMA_VERSION
            && self.task_run_id == task_run_id
            && self.entries.iter().enumerate().all(|(index, entry)| {
                entry.sequence == u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1)
                    && runne_runtime_client::CanonicalId::parse(&entry.event_id).is_ok()
                    && entry
                        .attempt_id
                        .as_ref()
                        .is_none_or(|id| runne_runtime_client::CanonicalId::parse(id).is_ok())
            })
    }
}

pub fn checkpoint(
    store: &mut LocalStore,
    secure: &dyn runne_secure_store::SecureStore,
    scope: &ReplayScopeKey,
) -> Result<Option<ReplayCheckpoint>, AppCoreError> {
    store
        .authenticated_replay_checkpoint(secure, scope)
        .map_err(|error| map_store_error(&error))
}

pub fn snapshot(
    store: &mut LocalStore,
    secure: &dyn runne_secure_store::SecureStore,
    scope: &ReplayScopeKey,
    task_run_id: &str,
) -> Result<TaskRunProjection, AppCoreError> {
    let stored = store
        .authenticated_conversation_projection(secure, scope)
        .map_err(|error| map_store_error(&error))?;
    let Some(stored) = stored else {
        return Ok(TaskRunProjection::Missing);
    };
    if stored.binding_digest != scope.binding_digest
        || replay_persistence_digest(&stored.payload) != stored.digest
    {
        return Err(AppCoreError::LocalProjectionUnavailable);
    }
    let projection: StoredTaskRunProjection = match serde_json::from_slice(&stored.payload) {
        Ok(projection) => projection,
        Err(_) => {
            return Ok(TaskRunProjection::AuthenticatedOpaque {
                revision: stored.revision,
                stream_version: stored.event_sequence,
            });
        }
    };
    if projection.projection_revision != stored.revision
        || projection.stream_version != stored.event_sequence
        || !projection.valid(task_run_id)
    {
        return Err(AppCoreError::LocalProjectionUnavailable);
    }
    Ok(TaskRunProjection::Decoded(projection))
}

pub fn apply_delivery(
    store: &mut LocalStore,
    secure: &dyn runne_secure_store::SecureStore,
    scope: &ReplayScopeKey,
    identity: &StableRuntimeIdentity,
    task_run_id: &str,
    delivery: &ReplayDelivery,
) -> Result<Option<TaskRunTimelineUpdate>, AppCoreError> {
    let event = delivery.event();
    if event.aggregate_kind() != ReplayAggregateKind::TaskRun
        || event.aggregate_id().to_string() != task_run_id
    {
        return Err(AppCoreError::RuntimeIdentityConflict);
    }
    let checkpoint = checkpoint(store, secure, scope)?;
    let mut projection = match snapshot(store, secure, scope, task_run_id)? {
        TaskRunProjection::Missing => StoredTaskRunProjection::empty(task_run_id),
        TaskRunProjection::Decoded(value) => value,
        TaskRunProjection::AuthenticatedOpaque { .. } => {
            return Err(AppCoreError::ReplayResyncRequired);
        }
    };
    if checkpoint
        .as_ref()
        .is_some_and(|current| event.sequence() < current.event_sequence)
    {
        let result = delivery.persist_with(|handoff| {
            let applied = runne_local_store::AppliedReplayEvent {
                scope,
                event_id: &event.event_id().to_string(),
                cursor: handoff.cursor_value(),
                generation: identity.launch_generation,
                event_sequence: event.sequence(),
                event_bytes: handoff.canonical_event_bytes(),
                event_digest: handoff.event_digest(),
            };
            store.authenticated_confirm_replay_event_applied(secure, &applied)
        });
        return match result.map_err(|error| map_store_error(&error))? {
            ReplayApplyOutcome::AlreadyApplied { .. } => Ok(None),
            ReplayApplyOutcome::Applied { .. } => Err(AppCoreError::RuntimeIdentityConflict),
        };
    }
    let duplicate = checkpoint
        .as_ref()
        .is_some_and(|current| current.event_sequence == event.sequence());
    let entry = if duplicate {
        None
    } else {
        if projection.stream_version.checked_add(1) != Some(event.sequence()) {
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let CanonicalReplayPayload::TaskRun(payload) = event.payload() else {
            return Err(AppCoreError::RuntimeIdentityConflict);
        };
        let entry = TaskRunTimelineEntry {
            event_id: event.event_id().to_string(),
            sequence: event.sequence(),
            committed_at: event.timestamp_unix_micros(),
            kind: payload.kind(),
            attempt_id: payload.attempt_id().map(|id| id.to_string()),
        };
        projection.entries.push(entry.clone());
        projection.stream_version = event.sequence();
        projection.projection_revision = projection
            .projection_revision
            .checked_add(1)
            .ok_or(AppCoreError::LocalProjectionUnavailable)?;
        Some(entry)
    };
    let bytes =
        serde_json::to_vec(&projection).map_err(|_| AppCoreError::LocalProjectionUnavailable)?;
    let digest = replay_persistence_digest(&bytes);
    let generation = checkpoint
        .as_ref()
        .map_or(identity.launch_generation, |value| value.generation);
    let result = delivery.persist_with(|handoff| {
        let transition = ReplayTransition {
            scope,
            expected_checkpoint: checkpoint.as_ref(),
            event_id: &event.event_id().to_string(),
            cursor: handoff.cursor_value(),
            generation,
            event_sequence: event.sequence(),
            event_bytes: handoff.canonical_event_bytes(),
            event_digest: handoff.event_digest().to_owned(),
            projection_revision: projection.projection_revision,
            projection_bytes: &bytes,
            projection_digest: digest,
        };
        store.apply_anchored_replay_transition(secure, &transition)
    });
    match result.map_err(|error| map_store_error(&error))? {
        ReplayApplyOutcome::AlreadyApplied { .. } => Ok(None),
        ReplayApplyOutcome::Applied { .. } => Ok(Some(TaskRunTimelineUpdate {
            task_run_id: task_run_id.to_owned(),
            projection_revision: projection.projection_revision,
            stream_version: projection.stream_version,
            entry,
            recovery: crate::TaskRunRecoveryDisposition::Live,
        })),
    }
}
