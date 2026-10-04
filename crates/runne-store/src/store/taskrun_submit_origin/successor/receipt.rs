use super::*;

pub(super) struct SuccessorReceiptVerification<'a> {
    pub(super) taskrun_id: TaskRunId,
    pub(super) conversation: ConversationId,
    pub(super) workspace: runne_domain::id::WorkspaceId,
    pub(super) input: &'a TaskRunInput,
    pub(super) scope: &'a runne_application::ports::IdempotencyScope,
    pub(super) command_id: CommandId,
    pub(super) key: &'a [u8],
    pub(super) fingerprint: &'a [u8],
    pub(super) outcome: &'a [u8],
    pub(super) original: &'a VerifiedTaskRunSubmitOrigin,
}

pub(super) fn verify_receipt(
    connection: &Connection,
    input: SuccessorReceiptVerification<'_>,
) -> Result<runne_domain::id::ProjectId, CommitError> {
    let SuccessorReceiptVerification {
        taskrun_id,
        conversation,
        workspace,
        input,
        scope,
        command_id,
        key,
        fingerprint,
        outcome,
        original,
    } = input;
    let row: Option<SuccessorReceipt> = connection.query_row(
        "SELECT predecessor_taskrun_id,conversation_id,workspace_id,principal_id,principal_digest,
                origin_kind,project_id,origin_operation,predecessor_input_digest,typed_input_digest,
                provider_id,profile_id,profile_digest,model_id,model_revision,model_ref_digest,
                successor_submit_event_id,successor_submit_version,command_id,idempotency_key_digest,
                command_fingerprint,acknowledgement_code,acknowledgement_version,acknowledgement_digest,
                predecessor_event_version,generation_superseded_version,
                occupation_release_event_id,occupation_release_version,occupation_release_reason,
                predecessor_event_id
         FROM taskrun_unknown_successor_receipts WHERE successor_taskrun_id=?1",
        [taskrun_id.as_bytes()], SuccessorReceipt::read,
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some(mut row) = row else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    let release_version = row
        .release_version
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let predecessor_version = row
        .predecessor_event_version
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let expected_version = if row.release_reason == "user_supersession" {
        predecessor_version
            .checked_sub(1)
            .filter(|version| *version > 0)
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?
    } else if matches!(
        row.release_reason.as_str(),
        "terminal_settlement" | "no_effect_release"
    ) {
        predecessor_version
    } else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    row.expected_version = expected_version;
    row.predecessor_version = predecessor_version;
    let project_bytes = row
        .project
        .as_deref()
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let project_bytes: [u8; 16] = project_bytes
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let project_id = runne_domain::id::ProjectId::from_bytes(project_bytes);
    let predecessor = TaskRunId::from_bytes(fixed(row.predecessor)?);
    let release_event = fixed(
        row.release_event_id
            .clone()
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?,
    )?;
    if fixed(
        row.predecessor_event_id
            .clone()
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?,
    )? != release_event
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let release_matches: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE aggregate_type=1 AND aggregate_id=?1
         AND sequence=?2 AND event_id=?3)",
            rusqlite::params![
                predecessor.as_bytes(),
                release_version,
                release_event.as_slice()
            ],
            |record| record.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !release_matches {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if scope.aggregate_scope
        != (AggregateScope::ExistingTaskRun {
            taskrun_id: predecessor,
        })
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let principal = &scope.principal_id.0;
    if original.principal_id.0 != *principal
        || original.conversation_id != conversation
        || original.workspace_id != workspace
        || original.project_id != Some(project_id)
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let profile = input
        .selected_profile()
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let model = runne_provider::ModelRef::new(
        runne_provider::ProviderId::new(row.provider.clone())
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        row.model.clone(),
        row.revision.clone(),
    )
    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let principal_digest = digest(
        b"runne-unknown-successor-principal\x01",
        principal.as_bytes(),
    );
    let key_digest = digest(b"runne-unknown-successor-idempotency\x01", key);
    let command_input = runne_application::commands::SupersedeUnknownTaskRunInput {
        predecessor_taskrun_id: predecessor,
        expected_predecessor_version: u64::try_from(row.expected_version)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        acknowledgment: runne_application::commands::UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1,
    };
    let recomputed_fingerprint =
        runne_application::fingerprint::CommandFingerprint::for_supersede_unknown_task_run(
            &command_input,
        );
    let typed_digest = runne_application::fingerprint::CommandFingerprint::for_submit(
        &conversation,
        &workspace,
        input,
    );
    let original_digest = runne_application::fingerprint::CommandFingerprint::for_submit(
        &conversation,
        &workspace,
        &original.input,
    );
    let selected_model = input.requested_model();
    let decoded_outcome = CommandOutcomeCodec
        .decode(outcome)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let outcome_matches = matches!(decoded_outcome,
        runne_application::commands::CommandOutcome::UnknownSuccessorCreated {
            predecessor_taskrun_id, predecessor_version, conversation_id, conversation_version,
            successor_taskrun_id, successor_version,
        } if predecessor_taskrun_id == predecessor && i64::try_from(predecessor_version).ok() == Some(row.predecessor_version)
            && conversation_id == conversation && conversation_version > 0
            && row.generation_version.is_none_or(|version| version == conversation_version as i64)
            && successor_taskrun_id == taskrun_id && successor_version == 2);
    if row.conversation.as_slice() != conversation.as_bytes()
        || row.workspace.as_slice() != workspace.as_bytes()
        || row.principal != principal.as_str()
        || row.principal_digest.as_slice() != principal_digest
        || row.origin_kind != "canonical_workspace"
        || row.project.is_none()
        || row.operation != 24
        || row.original_digest.as_slice() != original_digest.as_bytes()
        || row.typed_digest.as_slice() != typed_digest.as_bytes()
        || row.provider != model.provider_id().as_str()
        || row.profile != profile.profile_id()
        || row.profile_digest.as_slice() != profile.profile_digest()
        || selected_model != Some(row.model.as_str())
        || row.model_ref_digest.as_slice() != model.digest_v1()
        || row.submit_id.as_slice() != event_id(connection, taskrun_id)?.as_slice()
        || row.submit_version != 1
        || row.ack_code != "duplicate_execution_and_cost_v1"
        || row.ack_version != 1
        || row.ack_digest.as_slice() != acknowledgement_digest()
        || row.command_id.as_slice() != command_id.as_bytes()
        || row.command_fingerprint.as_slice() != fingerprint
        || fingerprint != recomputed_fingerprint.as_bytes()
        || row.key_digest.as_slice() != key_digest
        || row.predecessor_event_version != Some(row.predecessor_version)
        || row.release_event_id.is_none()
        || row.release_version != Some(row.predecessor_version)
        || !outcome_matches
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    verify_historical_workspace(connection, principal, workspace, row.project.as_deref())?;
    Ok(project_id)
}

struct SuccessorReceipt {
    predecessor: Vec<u8>,
    conversation: Vec<u8>,
    workspace: Vec<u8>,
    principal: String,
    principal_digest: Vec<u8>,
    origin_kind: String,
    project: Option<Vec<u8>>,
    operation: i64,
    original_digest: Vec<u8>,
    typed_digest: Vec<u8>,
    provider: String,
    profile: String,
    profile_digest: Vec<u8>,
    model: String,
    revision: String,
    model_ref_digest: Vec<u8>,
    submit_id: Vec<u8>,
    submit_version: i64,
    command_id: Vec<u8>,
    key_digest: Vec<u8>,
    command_fingerprint: Vec<u8>,
    ack_code: String,
    ack_version: i64,
    ack_digest: Vec<u8>,
    predecessor_event_version: Option<i64>,
    generation_version: Option<i64>,
    release_event_id: Option<Vec<u8>>,
    release_version: Option<i64>,
    release_reason: String,
    predecessor_event_id: Option<Vec<u8>>,
    expected_version: i64,
    predecessor_version: i64,
}

impl SuccessorReceipt {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            predecessor: row.get(0)?,
            conversation: row.get(1)?,
            workspace: row.get(2)?,
            principal: row.get(3)?,
            principal_digest: row.get(4)?,
            origin_kind: row.get(5)?,
            project: row.get(6)?,
            operation: row.get(7)?,
            original_digest: row.get(8)?,
            typed_digest: row.get(9)?,
            provider: row.get(10)?,
            profile: row.get(11)?,
            profile_digest: row.get(12)?,
            model: row.get(13)?,
            revision: row.get(14)?,
            model_ref_digest: row.get(15)?,
            submit_id: row.get(16)?,
            submit_version: row.get(17)?,
            command_id: row.get(18)?,
            key_digest: row.get(19)?,
            command_fingerprint: row.get(20)?,
            ack_code: row.get(21)?,
            ack_version: row.get(22)?,
            ack_digest: row.get(23)?,
            predecessor_event_version: row.get(24)?,
            generation_version: row.get(25)?,
            release_event_id: row.get(26)?,
            release_version: row.get(27)?,
            release_reason: row.get(28)?,
            predecessor_event_id: row.get(29)?,
            expected_version: 0,
            predecessor_version: 0,
        })
    }
}
