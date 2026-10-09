#[path = "project_workspace_sqlite/support.rs"]
#[allow(dead_code)]
mod support;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

#[path = "approval_host/conflicts.rs"]
mod conflicts;
#[path = "approval_host/decisions.rs"]
mod decisions;

use runne_api::{
    ApiActor, ApiPrincipalId, ApprovalCommandContext, ApprovalCommandHostPort,
    ApprovalCreateCommand, ApprovalDecision, ApprovalDecisionCommand, ApprovalHostError,
    ApprovalQueryContext, ApprovalQueryHostPort, ApprovalRequestHostPort, ApprovalState,
};
use runne_domain::id::{ApprovalId, InvocationId, TaskRunId};
use rusqlite::params;

fn id(tail: u8) -> [u8; 16] {
    [
        0x01, 0x8f, 0x47, 0xa2, 0x4f, 0x8c, 0x7b, 0x52, 0x8c, 0x35, 0x7a, 0x3a, 0x14, 0xc2, 0xd9,
        tail,
    ]
}

fn context(command_tail: u8, key: &str) -> ApprovalCommandContext {
    ApprovalCommandContext {
        command_id: runne_domain::id::CommandId::from_bytes(id(command_tail)),
        idempotency_key: runne_domain::id::IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("owner").unwrap(),
        actor: ApiActor::new("desktop").unwrap(),
    }
}

fn command(approval_id: ApprovalId) -> ApprovalDecisionCommand {
    ApprovalDecisionCommand::new(approval_id, 1, ApprovalDecision::Approve, [0x42; 32], 7, 3)
        .unwrap()
}

fn request_decision(
    approval_id: ApprovalId,
    decision: ApprovalDecision,
) -> ApprovalDecisionCommand {
    ApprovalDecisionCommand::new(approval_id, 1, decision, [0x52; 32], 7, 3).unwrap()
}

fn changed_binding_decisions(
    approval_id: ApprovalId,
    decision: ApprovalDecision,
) -> [ApprovalDecisionCommand; 3] {
    [
        ApprovalDecisionCommand::new(approval_id, 1, decision, [0x53; 32], 7, 3).unwrap(),
        ApprovalDecisionCommand::new(approval_id, 1, decision, [0x52; 32], 8, 3).unwrap(),
        ApprovalDecisionCommand::new(approval_id, 1, decision, [0x52; 32], 7, 4).unwrap(),
    ]
}

fn create_command(approval_id: ApprovalId, action: &str) -> ApprovalCreateCommand {
    ApprovalCreateCommand::new(
        approval_id,
        TaskRunId::from_bytes(id(0x71)),
        None,
        InvocationId::from_bytes(id(0x72)),
        ApiPrincipalId::new("owner").unwrap(),
        action,
        "workspace",
        [0x52; 32],
        7,
        3,
        i64::MAX,
        "requires approval",
    )
    .unwrap()
}

fn seed_pending(database: &support::Database, approval_id: ApprovalId, expires_at: i64) {
    let connection = database.connection();
    connection
        .execute(
            "INSERT INTO approvals (approval_id, task_run_id, attempt_id, invocation_id,
             principal_id, action, resource, action_digest, policy_revision, request_version,
             renderer_generation, expires_at, risk_summary, state, updated_at)
             VALUES (?1, ?2, NULL, ?3, 'owner', 'execute', 'workspace', ?4, 7, 1, 3, ?5,
             'requires approval', 1, 100)",
            params![
                approval_id.to_string(),
                TaskRunId::from_bytes(id(0x31)).to_string(),
                InvocationId::from_bytes(id(0x32)).to_string(),
                [0x42_u8; 32].as_slice(),
                expires_at,
            ],
        )
        .unwrap();
}
