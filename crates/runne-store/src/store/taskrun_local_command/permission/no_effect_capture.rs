use super::codec;
use runne_application::ports::{
    EventStoreError, ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence,
};
use runne_domain::id::TaskRunId;
use rusqlite::{Connection, OptionalExtension};

struct SavedCurrent {
    attempt: Vec<u8>,
    fence: i64,
    invocation: Vec<u8>,
    digest: Vec<u8>,
    bytes: Vec<u8>,
    owner: Vec<u8>,
    owner_generation: Vec<u8>,
    conversation: Vec<u8>,
    workspace: Vec<u8>,
    command: Vec<u8>,
    local_attempt: Option<Vec<u8>>,
    local_node: Option<Vec<u8>>,
    local_epoch: Option<i64>,
    local_fence: Option<i64>,
    state: String,
    area: Option<Vec<u8>>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i64>,
    approval: Option<Vec<u8>>,
}

pub(super) fn load_capture(
    connection: &Connection,
    taskrun_id: TaskRunId,
    expected_attempt: Option<runne_domain::id::AttemptId>,
    terminal: bool,
) -> Result<Option<(codec::CaptureV1, TaskRunAssignmentIdentity)>, EventStoreError> {
    let row: Option<SavedCurrent> = connection
        .query_row(
            "SELECT b.attempt_id,b.fence,b.invocation_id,b.binding_digest,b.binding,b.native_owner_id,b.native_owner_generation,
                    a.conversation_id,a.workspace_id,a.command_digest,a.attempt_id,a.node_id,a.node_epoch,a.fence,a.state,
                    a.managed_area_identity,a.stdout,a.stderr,a.exit_code,a.approval_id
             FROM x2_permission_bindings b JOIN taskrun_local_command_attempts a USING(taskrun_id)
             WHERE b.taskrun_id=?1 AND EXISTS(SELECT 1 FROM taskrun_local_permission_routes r
               WHERE r.taskrun_id=b.taskrun_id AND r.route=2 AND r.provenance=3 AND r.cutover_version=68)
               AND a.executable_digest IS NULL AND a.workspace_version IS NULL
               AND a.admitted_root_version IS NULL AND a.admitted_root_identity IS NULL
               AND a.trust_epoch IS NULL AND a.trust_revision IS NULL
               AND a.source_policy_version IS NULL AND a.command_policy_version IS NULL",
            [taskrun_id.as_bytes()],
            |row| {
                Ok(SavedCurrent {
                    attempt: row.get(0)?,
                    fence: row.get(1)?,
                    invocation: row.get(2)?,
                    digest: row.get(3)?,
                    bytes: row.get(4)?,
                    owner: row.get(5)?,
                    owner_generation: row.get(6)?,
                    conversation: row.get(7)?,
                    workspace: row.get(8)?,
                    command: row.get(9)?,
                    local_attempt: row.get(10)?,
                    local_node: row.get(11)?,
                    local_epoch: row.get(12)?,
                    local_fence: row.get(13)?,
                    state: row.get(14)?,
                    area: row.get(15)?,
                    stdout: row.get(16)?,
                    stderr: row.get(17)?,
                    exit_code: row.get(18)?,
                    approval: row.get(19)?,
                })
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some(row) = row else { return Ok(None) };
    let record = codec::decode(&row.bytes).map_err(|_| EventStoreError::CorruptData)?;
    let attempt: [u8; 16] = row
        .attempt
        .as_slice()
        .try_into()
        .map_err(|_| EventStoreError::CorruptData)?;
    let node = uuid::Uuid::parse_str(&record.node_id).map_err(|_| EventStoreError::CorruptData)?;
    let state_ok = if terminal {
        row.state == "no_effect_terminal"
    } else {
        matches!(row.state.as_str(), "approval_pending" | "approved")
    };
    if !codec::digest_matches(&row.bytes, &row.digest)
        || record.taskrun_id != *taskrun_id.as_bytes()
        || record.attempt_id != attempt
        || record.fence != u64::try_from(row.fence).map_err(|_| EventStoreError::CorruptData)?
        || record.invocation_id.as_slice() != row.invocation.as_slice()
        || record.native_owner_id.as_slice() != row.owner.as_slice()
        || record.native_owner_generation.to_be_bytes().as_slice()
            != row.owner_generation.as_slice()
        || record.node_epoch == 0
        || record.fence == 0
        || record.claim_stream_version == 0
        || node.is_nil()
        || node.to_string() != record.node_id
        || row.conversation.len() != 16
        || row.workspace.len() != 16
        || record.workspace_id.as_slice() != row.workspace.as_slice()
        || record.command_digest.as_slice() != row.command.as_slice()
        || row.local_attempt.as_deref() != Some(attempt.as_slice())
        || row.local_node.as_deref() != Some(node.as_bytes().as_slice())
        || row.local_epoch != i64::try_from(record.node_epoch).ok()
        || row.local_fence != Some(row.fence)
        || !state_ok
        || expected_attempt.is_some_and(|value| *value.as_bytes() != attempt)
        || row.area.is_some()
        || !row.stdout.is_empty()
        || !row.stderr.is_empty()
        || row.exit_code.is_some()
        || row.approval.is_some()
    {
        return Ok(None);
    }
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
        connection, taskrun_id,
    )
    .map_err(|_| EventStoreError::CorruptData)?
    .ok_or(EventStoreError::CorruptData)?;
    let Some(command) = origin.input.local_command() else {
        return Ok(None);
    };
    if origin.conversation_id.as_bytes() != row.conversation.as_slice()
        || origin.workspace_id.as_bytes() != row.workspace.as_slice()
        || origin.principal_id.0 != record.principal_id
        || origin.project_id.map(|value| *value.as_bytes()) != Some(record.project_id)
        || command.intent_digest() != record.command_digest
    {
        return Ok(None);
    }
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: runne_domain::id::AttemptId::from_bytes(attempt),
        node_id: ExecutionNodeId(node.to_string()),
        node_epoch: record.node_epoch,
        fence: TaskRunFence(record.fence),
    };
    Ok(Some((record, identity)))
}
