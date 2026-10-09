use runne_domain::id::{ConversationId, TaskRunId, WorkspaceId};
use runne_domain::task_run::TaskRunEvent;
use rusqlite::{Transaction, params};

pub(crate) mod effects_proof;
mod launch;
mod lifecycle;
pub(crate) mod permission;
mod recovery;
mod run;
#[cfg(target_os = "linux")]
mod settlement;
pub use lifecycle::{LocalCommandApprovalBinding, LocalCommandAttemptState};
#[cfg(target_os = "linux")]
pub use permission::LocalCommandPermissionTerminalOutputV1;
pub use permission::{
    LocalCommandPermissionCaptureV1, LocalCommandPermissionRoute, PermissionRootFenceGuardV1,
    PermissionRootFenceOwnerV1, PermissionRootFenceRequestV1,
};
pub use recovery::LocalCommandRecoveryCandidate;

pub(super) fn insert_preflight(
    tx: &Transaction<'_>,
    taskrun_id: TaskRunId,
    event: &TaskRunEvent,
    now: i64,
) -> rusqlite::Result<()> {
    let TaskRunEvent::TaskRunSubmitted {
        conversation_id,
        workspace_id,
        input,
    } = event
    else {
        return Ok(());
    };
    let Some(command) = input.local_command() else {
        return Ok(());
    };
    insert_preflight_row(
        tx,
        taskrun_id,
        *conversation_id,
        *workspace_id,
        &command.intent_digest(),
        now,
    )
}

fn insert_preflight_row(
    tx: &Transaction<'_>,
    taskrun_id: TaskRunId,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    command_digest: &[u8; 32],
    now: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO taskrun_local_command_attempts
         (taskrun_id,conversation_id,workspace_id,command_digest,state,updated_at)
         VALUES (?1,?2,?3,?4,'preflight',?5)",
        params![
            taskrun_id.as_bytes(),
            conversation_id.as_bytes(),
            workspace_id.as_bytes(),
            command_digest,
            now
        ],
    )?;
    tx.execute(
        "INSERT INTO taskrun_local_permission_routes
         (taskrun_id,route,provenance,cutover_version) VALUES (?1,2,3,68)",
        [taskrun_id.as_bytes()],
    )?;
    Ok(())
}
