use super::super::*;
use runne_application::ports::{
    CommitError, ExecutionNodeId, StorageFailureKind, TaskRunAssignmentIdentity, TaskRunFence,
};
use runne_application::provider::{
    HistoricalProviderModelResolver, HistoricalProviderProfileIdentity,
};
use runne_domain::conversation::{Conversation, ConversationContextScope};
use runne_domain::id::{ProjectId, WorkspaceId};
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_provider::ProviderId;
use rusqlite::{OptionalExtension, Transaction, params};

use runne_application::ports::UnknownSuccessorCommit;
mod origin;
include!("validate/assignment.rs");
mod provider_unknown;
use origin::canonical_origin;
use provider_unknown::provider_unknown;

pub(super) struct BoundSuccessor {
    pub conversation_id: ConversationId,
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub original_input: TaskRunInput,
    pub successor_input: TaskRunInput,
    pub attempt_id: AttemptId,
    pub node_id: [u8; 16],
    pub node_epoch: u64,
    pub predecessor_event_id: EventId,
    pub predecessor_event_version: u64,
    pub dispatch_attempt_id: [u8; 16],
    pub provider_id: String,
    pub profile_id: String,
    pub profile_digest: [u8; 32],
    pub model_id: String,
    pub model_revision: String,
    pub fence: i64,
    pub release_event: [u8; 16],
    pub release_version: i64,
    pub release_reason: &'static str,
    pub conversation_version: u64,
    pub conversation_tail: Option<EventId>,
    pub add_generation_marker: bool,
    pub origin_principal: String,
}

pub(super) fn validate(
    tx: &Transaction<'_>,
    payload: &UnknownSuccessorCommit,
    resolver: &dyn HistoricalProviderModelResolver,
) -> Result<BoundSuccessor, CommitError> {
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
        tx,
        payload.predecessor_taskrun_id,
        &payload.idempotency_scope.runtime_authority_id,
    )?
    .ok_or_else(|| fail(StorageFailureKind::PolicyDenied))?;
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        tx,
        payload.predecessor_taskrun_id,
        Some(payload.expected_predecessor_version),
    )
    .map_err(|_| CommitError::VersionConflict {
        expected: payload.expected_predecessor_version,
        actual: 0,
    })?;
    let append_predecessor = matches!(
        stream.state,
        runne_domain::task_run::TaskRunState::Running
            | runne_domain::task_run::TaskRunState::Cancelling
    );
    if !append_predecessor {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let replayed = runne_domain::task_run::TaskRun::replay(&stream.events)
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let attempt_id = stream
        .active_attempt
        .or_else(|| replayed.attempt_history().last().copied())
        .ok_or_else(|| fail(StorageFailureKind::CorruptData))?;
    if origin.input.local_command().is_some()
        || origin.principal_id != payload.idempotency_scope.principal_id
    {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let project_id = canonical_origin(tx, &origin, payload)?;
    require_conversation_writer(tx, origin.conversation_id, &origin.principal_id.0)?;
    let already_superseded: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_unknown_successor_receipts WHERE predecessor_taskrun_id=?1)",
        [payload.predecessor_taskrun_id.as_bytes()], |row| row.get(0),
    ).map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if already_superseded {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let local_attempt_exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1)",
            [payload.predecessor_taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if local_attempt_exists {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let (dispatch_attempt_id, provider_id, profile_id, profile_digest) =
        provider_unknown(tx, payload.predecessor_taskrun_id, attempt_id)?;
    let assignment =
        active_assignment(tx, payload.predecessor_taskrun_id, attempt_id, stream.state)?;
    let release_event = payload.event_ids[0];
    let release_version = stream
        .version
        .checked_add(1)
        .ok_or_else(|| fail(StorageFailureKind::IntegrityViolation))?;
    let release_reason = "user_supersession";
    if origin.input.selected_profile().is_some_and(|selected| {
        selected.profile_id() != profile_id
            || selected.profile_digest().as_slice() != profile_digest
    }) {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let provider =
        ProviderId::new(provider_id.clone()).map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let identity =
        HistoricalProviderProfileIdentity::new(provider, profile_id.clone(), profile_digest)
            .map_err(|_| fail(StorageFailureKind::PolicyDenied))?;
    let model = resolver
        .resolve_exact(&identity)
        .map_err(|_| fail(StorageFailureKind::PolicyDenied))?;
    if model.provider_id().as_str() != provider_id
        || origin
            .input
            .requested_model()
            .is_some_and(|requested| requested != model.model_id())
    {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let selected_profile = SelectedProviderProfile::new(profile_id.clone(), profile_digest)
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let successor_input = TaskRunInput::new(origin.input.prompt().to_owned())
        .and_then(|input| input.with_requested_model(model.model_id().to_owned()))
        .and_then(|input| input.with_selected_profile(selected_profile))
        .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    let loaded =
        crate::store::conversation::load_conversation_from_connection(tx, origin.conversation_id)
            .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let conversation =
        Conversation::replay(&loaded.events).map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if conversation.workspace_id != origin.workspace_id
        || conversation.state != runne_domain::conversation::ConversationState::Active
    {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let active = conversation.active_generation();
    let add_generation_marker = match active {
        Some(active)
            if active.taskrun_id == payload.predecessor_taskrun_id
                && active.attempt_id == attempt_id =>
        {
            true
        }
        Some(_) => return Err(fail(StorageFailureKind::PolicyDenied)),
        None => false,
    };
    let scope: Option<String> = tx
        .query_row(
            "SELECT context_scope FROM conversation_context_scope WHERE conversation_id=?1",
            [origin.conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if scope.as_deref() != Some(ConversationContextScope::Workspace.as_str()) {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    Ok(BoundSuccessor {
        conversation_id: origin.conversation_id,
        workspace_id: origin.workspace_id,
        project_id,
        original_input: origin.input,
        successor_input,
        attempt_id,
        node_id: uuid::Uuid::parse_str(&assignment.node_id.0)
            .map_err(|_| fail(StorageFailureKind::CorruptData))?
            .into_bytes(),
        node_epoch: assignment.node_epoch,
        predecessor_event_id: release_event,
        predecessor_event_version: release_version,
        dispatch_attempt_id,
        provider_id,
        profile_id,
        profile_digest,
        model_id: model.model_id().to_owned(),
        model_revision: model.revision().to_owned(),
        fence: assignment.fence.0 as i64,
        release_event: *release_event.as_bytes(),
        release_version: release_version as i64,
        release_reason,
        conversation_version: loaded.current_version,
        conversation_tail: loaded.last_event_id,
        add_generation_marker,
        origin_principal: origin.principal_id.0,
    })
}

fn require_conversation_writer(
    tx: &Transaction<'_>,
    conversation_id: ConversationId,
    principal: &str,
) -> Result<(), CommitError> {
    let owner: Option<(String, i64)> = tx
        .query_row(
            "SELECT owner_principal,fencing_token FROM conversation_writer_leases
             WHERE conversation_id=?1",
            [conversation_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if owner.is_none_or(|(owner, fence)| owner != principal || fence <= 0) {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    Ok(())
}

fn fail(kind: StorageFailureKind) -> CommitError {
    CommitError::StorageFailure(kind)
}
