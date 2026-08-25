#[path = "project_workspace_sqlite/support.rs"]
#[allow(dead_code)]
mod support;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

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

#[tokio::test(flavor = "current_thread")]
async fn identical_approval_decision_retry_returns_the_durable_ack() {
    let database = support::Database::new("approval-idempotent-retry");
    let repository = database.repository();
    let approval_id = ApprovalId::from_bytes(id(0x30));
    seed_pending(&database, approval_id, i64::MAX);
    let context = context(0x40, "approval-decision");
    let command = command(approval_id);

    let first = repository
        .decide_approval(context.clone(), command.clone())
        .await
        .unwrap();
    let second = repository.decide_approval(context, command).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(first.state(), ApprovalState::Approved);
    assert_eq!(first.new_version(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn expired_approval_is_terminal_and_reports_expired() {
    let database = support::Database::new("approval-expiry");
    let repository = database.repository();
    let approval_id = ApprovalId::from_bytes(id(0x50));
    seed_pending(&database, approval_id, 1);

    let result = repository
        .decide_approval(context(0x60, "expired-approval"), command(approval_id))
        .await;

    assert_eq!(result, Err(ApprovalHostError::Expired));
    let summary = repository
        .get_approval(
            ApprovalQueryContext {
                principal: ApiPrincipalId::new("owner").unwrap(),
            },
            approval_id,
        )
        .await
        .unwrap();
    assert_eq!(summary.state(), ApprovalState::Expired);
}

#[tokio::test(flavor = "current_thread")]
async fn creating_an_approval_is_durable_and_same_id_is_idempotent() {
    let database = support::Database::new("approval-create");
    let repository = database.repository();
    let approval_id = ApprovalId::from_bytes(id(0x70));
    let request = create_command(approval_id, "execute");

    let first = repository
        .create_pending_approval(request.clone())
        .await
        .unwrap();
    let second = repository.create_pending_approval(request).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(first.state(), ApprovalState::Pending);
    assert_eq!(
        repository
            .list_pending_approvals(ApprovalQueryContext {
                principal: ApiPrincipalId::new("owner").unwrap(),
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn same_approval_id_cannot_replace_a_different_request() {
    let database = support::Database::new("approval-create-conflict");
    let repository = database.repository();
    let approval_id = ApprovalId::from_bytes(id(0x73));

    repository
        .create_pending_approval(create_command(approval_id, "execute"))
        .await
        .unwrap();
    let result = repository
        .create_pending_approval(create_command(approval_id, "delete"))
        .await;

    assert_eq!(result, Err(ApprovalHostError::Conflict));
}

#[tokio::test(flavor = "current_thread")]
async fn expired_pending_approval_is_reconciled_before_query_results() {
    let database = support::Database::new("approval-query-expiry");
    let repository = database.repository();
    let approval_id = ApprovalId::from_bytes(id(0x74));
    seed_pending(&database, approval_id, 1);
    let context = ApprovalQueryContext {
        principal: ApiPrincipalId::new("owner").unwrap(),
    };

    let pending = repository
        .list_pending_approvals(context.clone())
        .await
        .unwrap();

    assert!(pending.is_empty());
    let summary = repository.get_approval(context, approval_id).await.unwrap();
    assert_eq!(summary.state(), ApprovalState::Expired);
}
