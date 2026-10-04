use super::*;
use crate::codec::{IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec};
use runne_application::ports::{RuntimeAuthorityId, TextGenerationPhase};
use runne_domain::conversation::{Conversation, ConversationEvent};
use runne_domain::id::{AttemptId, CommandId, ConversationId, TaskRunId};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
type BeginCommandReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

#[path = "remote_terminal_source_applicability.rs"]
mod applicability;
#[path = "remote_terminal_source_support.rs"]
mod support;
pub(crate) use applicability::RemoteTerminalTaskRunApplicability;

/// Source facts for an authenticated remote terminal artifact.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedRemoteTerminalTaskRunSource {
    pub(crate) taskrun_id: TaskRunId,
    pub(crate) taskrun_attempt_id: AttemptId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) original_principal: String,
    pub(crate) original_actor: String,
    pub(crate) writer_owner_principal: String,
    pub(crate) writer_fencing_token: u64,
    pub(crate) begin_command_id: CommandId,
    pub(crate) generation_id: [u8; 16],
    pub(crate) begin_event_digest: [u8; 32],
    pub(crate) expected_taskrun_version: u64,
    pub(crate) current_taskrun_version: u64,
    pub(crate) current_taskrun_state: TaskRunState,
    pub(crate) current_generation_active: bool,
    pub(crate) writer_lease_current: bool,
    pub(crate) publication_allowed: bool,
    pub(crate) applicability: RemoteTerminalTaskRunApplicability,
}

/// Verifies the original generation source and pins the current writer fence.
/// Call inside the caller's immediate transaction before inserting or applying
/// the remote settlement receipt. Existing receipts retain their original pin;
/// a later owner/fence change makes publication audit-only.
pub(crate) fn verify_remote_terminal_taskrun_source(
    connection: &Connection,
    dispatch_attempt_id: &[u8; 16],
    authority: &RuntimeAuthorityId,
) -> Result<VerifiedRemoteTerminalTaskRunSource, CommitError> {
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let (taskrun_bytes, attempt_bytes, provider_id, profile_id, profile_digest) =
        support::load_remote_profile_identity(connection, dispatch_attempt_id)?;
    let taskrun_id =
        TaskRunId::from_bytes(taskrun_bytes.as_slice().try_into().map_err(|_| {
            storage_failure(runne_application::ports::StorageFailureKind::CorruptData)
        })?);
    let attempt_id =
        AttemptId::from_bytes(attempt_bytes.as_slice().try_into().map_err(|_| {
            storage_failure(runne_application::ports::StorageFailureKind::CorruptData)
        })?);
    let taskrun =
        crate::store::taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let task = TaskRun::replay(&taskrun.events)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !task.attempt_history().contains(&attempt_id) {
        return Err(invalid());
    }
    let started_versions: Vec<u64> = taskrun
        .events
        .iter()
        .filter_map(|event| {
            matches!(event.payload(), TaskRunEvent::AttemptStarted { attempt_id: started }
                if *started == attempt_id)
            .then_some(event.sequence())
        })
        .collect();
    let [started_version] = started_versions.as_slice() else {
        return Err(invalid());
    };
    let origin = super::verify_submitted_v2_origin_for_readiness(connection, taskrun_id)?
        .ok_or_else(invalid)?;
    support::verify_selected_profile(&origin, &provider_id, &profile_id, &profile_digest)?;
    let start_index = usize::try_from(*started_version - 1)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let start_event = taskrun.events.get(start_index).ok_or_else(invalid)?;
    let admitted_event = start_index
        .checked_sub(1)
        .and_then(|index| taskrun.events.get(index))
        .ok_or_else(invalid)?;
    let start_key = start_event.idempotency_key().as_str().as_bytes();
    let admitted_event_id = admitted_event.event_id().as_bytes();
    let started_event_id = start_event.event_id().as_bytes();
    let claim_receipt_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND new_version=?3
               AND admitted_event_id=?4 AND started_event_id=?5
               AND command_id=?6 AND idempotency_key=?7",
            rusqlite::params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                i64::try_from(*started_version)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
                admitted_event_id,
                started_event_id,
                start_event.command_id().as_bytes(),
                start_key,
            ],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if admitted_event.sequence().checked_add(1) != Some(*started_version)
        || admitted_event.payload() != &TaskRunEvent::TaskRunAdmitted
        || admitted_event.command_id() != start_event.command_id()
        || admitted_event.idempotency_key() != start_event.idempotency_key()
        || admitted_event.actor() != start_event.actor()
        || start_event.actor() != &origin.actor
        || claim_receipt_count != 1
    {
        return Err(invalid());
    }
    let conversation_id = origin.conversation_id;
    let conversation_stream =
        crate::store::conversation::load_conversation_from_connection(connection, conversation_id)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let conversation = Conversation::replay(&conversation_stream.events)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let messages: Vec<_> = conversation_stream
        .events
        .iter()
        .filter(|event| {
            matches!(
                event.payload(),
                ConversationEvent::UserMessageAppended {
                    taskrun_id: event_taskrun,
                    attempt_id: event_attempt,
                    ..
                } if *event_taskrun == taskrun_id && *event_attempt == attempt_id
            )
        })
        .collect();
    let [message] = messages.as_slice() else {
        return Err(invalid());
    };
    let (begin_command_id, begin_key, scope_bytes, outcome, fingerprint): BeginCommandReceiptRow = connection
        .query_row(
            "SELECT command_id,idempotency_key,idempotency_scope_bytes,command_outcome,fingerprint
                 FROM command_receipts WHERE command_id=?1",
            [message.command_id().as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|_| invalid())?;
    let begin_command_id = CommandId::from_bytes(
        begin_command_id
            .as_slice()
            .try_into()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
    );
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let receipt = TextGenerationReceiptCodec
        .decode(&outcome)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    support::verify_begin_source(support::BeginSourceVerification {
        scope: &scope,
        receipt: &receipt,
        origin: &origin,
        taskrun_id,
        attempt_id,
        conversation_id,
        message,
        begin_key: &begin_key,
        fingerprint: &fingerprint,
        authority,
        expected_actor: &origin.actor,
    })?;
    if receipt.taskrun_version < *started_version
        || (receipt.phase == TextGenerationPhase::Started
            && receipt.taskrun_version != *started_version)
    {
        return Err(invalid());
    }
    let lease =
        crate::conversation_writer_lease::load_writer_lease(connection, conversation_id.as_bytes())
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?
            .ok_or_else(invalid)?;
    let current_generation_active = conversation
        .active_generation()
        .is_some_and(|active| active.taskrun_id == taskrun_id && active.attempt_id == attempt_id);
    let applicability = applicability::verify(
        connection,
        applicability::RemoteTaskRunApplicabilityFacts {
            taskrun_id,
            attempt_id,
            version: taskrun.version,
            state: task.state(),
            active_attempt: task.active_attempt(),
            events: &taskrun.events,
            authority,
            origin: &origin,
        },
    )?;
    let existing_pin: Option<support::WriterPin> = connection
        .query_row(
            "SELECT taskrun_id,taskrun_attempt_id,conversation_id,writer_owner_principal,writer_fencing_token,
                    begin_command_id,generation_id,begin_event_digest,expected_taskrun_version
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [dispatch_attempt_id.as_slice()],
            support::WriterPin::read,
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let event_digest = *message.integrity_digest().as_bytes();
    let expected_taskrun_version = if let Some(pin) = &existing_pin {
        if pin.taskrun_id.as_slice() != taskrun_id.as_bytes()
            || pin.taskrun_attempt_id.as_slice() != attempt_id.as_bytes()
            || pin.conversation_id.as_slice() != conversation_id.as_bytes()
            || pin.begin_command_id.as_slice() != begin_command_id.as_bytes()
            || pin.generation_id.as_slice() != attempt_id.as_bytes()
            || pin.begin_event_digest.as_slice() != event_digest
            || pin.expected_taskrun_version <= 0
            || u64::try_from(pin.expected_taskrun_version)
                .ok()
                .is_none_or(|version| version > taskrun.version)
        {
            return Err(invalid());
        }
        u64::try_from(pin.expected_taskrun_version)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
    } else {
        taskrun.version
    };
    let (writer_owner_principal, writer_fencing_token) = if let Some(pin) = existing_pin {
        (
            pin.writer_owner_principal,
            u64::try_from(pin.writer_fencing_token)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        )
    } else {
        (lease.owner_principal.clone(), lease.fencing_token)
    };
    let taskrun_is_current = taskrun.version == expected_taskrun_version
        && taskrun.active_attempt == Some(attempt_id)
        && matches!(
            task.state(),
            TaskRunState::Running | TaskRunState::Cancelling
        );
    let writer_is_current = lease.owner_principal == writer_owner_principal
        && lease.fencing_token == writer_fencing_token
        && writer_owner_principal == origin.principal_id.0;
    Ok(VerifiedRemoteTerminalTaskRunSource {
        taskrun_id,
        taskrun_attempt_id: attempt_id,
        conversation_id,
        original_principal: origin.principal_id.0,
        original_actor: origin.actor.as_str().to_owned(),
        writer_owner_principal,
        writer_fencing_token,
        begin_command_id,
        generation_id: *attempt_id.as_bytes(),
        begin_event_digest: event_digest,
        expected_taskrun_version,
        current_taskrun_version: taskrun.version,
        current_taskrun_state: task.state(),
        current_generation_active,
        writer_lease_current: writer_is_current,
        publication_allowed: taskrun_is_current
            && writer_is_current
            && current_generation_active
            && task.state() == TaskRunState::Running,
        applicability,
    })
}
