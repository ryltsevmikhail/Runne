use super::super::super::parse_helpers::storage_failure;
use super::VerifiedTaskRunSubmitOrigin;
use crate::conversation_writer_lease::ConversationWriterLease;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, CommitError, IdempotencyScope, OperationTag, RuntimeAuthorityId,
    StorageFailureKind, TextGenerationPhase, TextGenerationReceipt,
};
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::Actor;
use runne_domain::id::{AttemptId, CommandId, ConversationId, TaskRunId};
use runne_domain::task_run::TaskRunState;
use rusqlite::{Connection, OptionalExtension};

type RemoteProfileIdentityRow = (Vec<u8>, Vec<u8>, String, String, Vec<u8>);

pub(super) fn load_remote_profile_identity(
    connection: &Connection,
    dispatch_attempt_id: &[u8; 16],
) -> Result<RemoteProfileIdentityRow, CommitError> {
    connection
        .query_row(
            "SELECT q.taskrun_id,q.taskrun_attempt_id,q.provider_id,q.profile_id,q.profile_digest
             FROM provider_remote_request_intents q
             JOIN provider_dispatch_attempts a ON a.attempt_id=q.dispatch_attempt_id
             WHERE q.dispatch_attempt_id=?1",
            [dispatch_attempt_id.as_slice()],
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
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))
}

pub(super) struct SourceFinalizationInput<'a> {
    pub(super) connection: &'a Connection,
    pub(super) dispatch_attempt_id: &'a [u8; 16],
    pub(super) taskrun_id: TaskRunId,
    pub(super) attempt_id: AttemptId,
    pub(super) conversation_id: ConversationId,
    pub(super) taskrun_version: u64,
    pub(super) taskrun_active_attempt: Option<AttemptId>,
    pub(super) taskrun_state: TaskRunState,
    pub(super) current_generation_active: bool,
    pub(super) origin: &'a VerifiedTaskRunSubmitOrigin,
    pub(super) begin_command_id: CommandId,
    pub(super) begin_event_digest: [u8; 32],
    pub(super) lease: ConversationWriterLease,
    pub(super) applicability: super::RemoteTerminalTaskRunApplicability,
}

pub(super) fn finalize_remote_source(
    input: SourceFinalizationInput<'_>,
) -> Result<super::VerifiedRemoteTerminalTaskRunSource, CommitError> {
    let SourceFinalizationInput {
        connection,
        dispatch_attempt_id,
        taskrun_id,
        attempt_id,
        conversation_id,
        taskrun_version,
        taskrun_active_attempt,
        taskrun_state,
        current_generation_active,
        origin,
        begin_command_id,
        begin_event_digest,
        lease,
        applicability,
    } = input;
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let existing_pin: Result<Option<WriterPin>, CommitError> = connection
        .query_row(
            "SELECT taskrun_id,taskrun_attempt_id,conversation_id,writer_owner_principal,writer_fencing_token,
                    begin_command_id,generation_id,begin_event_digest,expected_taskrun_version
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [dispatch_attempt_id.as_slice()],
            WriterPin::read,
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData));
    let existing_pin =
        crate::store::test_support_diagnostics::on_error("source.existing_pin", existing_pin)?;
    let expected_taskrun_version = if let Some(pin) = &existing_pin {
        if pin.taskrun_id.as_slice() != taskrun_id.as_bytes()
            || pin.taskrun_attempt_id.as_slice() != attempt_id.as_bytes()
            || pin.conversation_id.as_slice() != conversation_id.as_bytes()
            || pin.begin_command_id.as_slice() != begin_command_id.as_bytes()
            || pin.generation_id.as_slice() != attempt_id.as_bytes()
            || pin.begin_event_digest.as_slice() != begin_event_digest
            || pin.expected_taskrun_version <= 0
            || u64::try_from(pin.expected_taskrun_version)
                .ok()
                .is_none_or(|version| version > taskrun_version)
        {
            return Err(invalid());
        }
        u64::try_from(pin.expected_taskrun_version)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
    } else {
        taskrun_version
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
    let taskrun_is_current = taskrun_version == expected_taskrun_version
        && taskrun_active_attempt == Some(attempt_id)
        && matches!(
            taskrun_state,
            TaskRunState::Running | TaskRunState::Cancelling
        );
    let writer_is_current = lease.owner_principal == writer_owner_principal
        && lease.fencing_token == writer_fencing_token
        && writer_owner_principal == origin.principal_id.0;
    Ok(super::VerifiedRemoteTerminalTaskRunSource {
        taskrun_id,
        taskrun_attempt_id: attempt_id,
        conversation_id,
        original_principal: origin.principal_id.0.clone(),
        original_actor: origin.actor.as_str().to_owned(),
        writer_owner_principal,
        writer_fencing_token,
        begin_command_id,
        generation_id: *attempt_id.as_bytes(),
        begin_event_digest,
        expected_taskrun_version,
        current_taskrun_version: taskrun_version,
        current_taskrun_state: taskrun_state,
        current_generation_active,
        writer_lease_current: writer_is_current,
        publication_allowed: taskrun_is_current
            && writer_is_current
            && current_generation_active
            && taskrun_state == TaskRunState::Running,
        applicability,
    })
}

pub(super) fn runtime_claim_scope_matches(
    scope: &IdempotencyScope,
    authority: &RuntimeAuthorityId,
    taskrun_id: TaskRunId,
    actor: &Actor,
) -> bool {
    scope.runtime_authority_id == *authority
        && scope.principal_id.0 == "runne-runtime"
        && scope.operation == OperationTag::TaskRunClaim
        && scope.aggregate_scope == (AggregateScope::ExistingTaskRun { taskrun_id })
        && actor.as_str() == "runne-runtime"
}

pub(super) struct BeginSourceVerification<'a> {
    pub(super) scope: &'a IdempotencyScope,
    pub(super) receipt: &'a TextGenerationReceipt,
    pub(super) origin: &'a VerifiedTaskRunSubmitOrigin,
    pub(super) taskrun_id: TaskRunId,
    pub(super) attempt_id: AttemptId,
    pub(super) conversation_id: ConversationId,
    pub(super) message: &'a runne_domain::event::EventEnvelope<ConversationEvent>,
    pub(super) begin_key: &'a [u8],
    pub(super) fingerprint: &'a [u8],
    pub(super) authority: &'a RuntimeAuthorityId,
    pub(super) expected_actor: &'a Actor,
}

pub(super) fn verify_begin_source(input: BeginSourceVerification<'_>) -> Result<(), CommitError> {
    let BeginSourceVerification {
        scope,
        receipt,
        origin,
        taskrun_id,
        attempt_id,
        conversation_id,
        message,
        begin_key,
        fingerprint,
        authority,
        expected_actor,
    } = input;
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let ConversationEvent::UserMessageAppended {
        message_id, text, ..
    } = message.payload()
    else {
        return Err(invalid());
    };
    let expected_version = message.sequence().checked_sub(1).ok_or_else(invalid)?;
    let expected_fingerprint = CommandFingerprint::for_generate_conversation_text(
        &conversation_id,
        expected_version,
        text,
    );
    let expected_receipt_version = match receipt.phase {
        TextGenerationPhase::Started => message.sequence(),
        TextGenerationPhase::Completed | TextGenerationPhase::Rejected => {
            message.sequence().checked_add(1).ok_or_else(invalid)?
        }
        TextGenerationPhase::ProhibitedInputRejected => return Err(invalid()),
    };
    if scope.runtime_authority_id != *authority
        || scope.operation != OperationTag::GenerateConversationText
        || scope.aggregate_scope != (AggregateScope::ExistingConversation { conversation_id })
        || scope.principal_id != origin.principal_id
        || message.actor() != expected_actor
        || receipt.conversation_id != conversation_id
        || receipt.taskrun_id != taskrun_id
        || receipt.attempt_id != attempt_id
        || receipt.user_message_id != *message_id
        || receipt.workspace_id != origin.workspace_id
        || begin_key != message.idempotency_key().as_str().as_bytes()
        || receipt.conversation_version != expected_receipt_version
        || fingerprint != expected_fingerprint.as_bytes()
        || text.as_str() != origin.input.prompt()
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn verify_selected_profile(
    origin: &VerifiedTaskRunSubmitOrigin,
    provider_id: &str,
    profile_id: &str,
    profile_digest: &[u8],
) -> Result<(), CommitError> {
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let profile = origin.input.selected_profile();
    let matches = profile.is_some_and(|selected| {
        selected.profile_id() == profile_id
            && selected.profile_digest().as_slice() == profile_digest
    });
    if matches || (profile.is_none() && provider_id != "openai-background") {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(super) struct WriterPin {
    pub(super) taskrun_id: Vec<u8>,
    pub(super) taskrun_attempt_id: Vec<u8>,
    pub(super) conversation_id: Vec<u8>,
    pub(super) writer_owner_principal: String,
    pub(super) writer_fencing_token: i64,
    pub(super) begin_command_id: Vec<u8>,
    pub(super) generation_id: Vec<u8>,
    pub(super) begin_event_digest: Vec<u8>,
    pub(super) expected_taskrun_version: i64,
}

impl WriterPin {
    pub(super) fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            taskrun_id: row.get(0)?,
            taskrun_attempt_id: row.get(1)?,
            conversation_id: row.get(2)?,
            writer_owner_principal: row.get(3)?,
            writer_fencing_token: row.get(4)?,
            begin_command_id: row.get(5)?,
            generation_id: row.get(6)?,
            begin_event_digest: row.get(7)?,
            expected_taskrun_version: row.get(8)?,
        })
    }
}

#[cfg(test)]
#[path = "remote_terminal_source_support_tests.rs"]
mod tests;
