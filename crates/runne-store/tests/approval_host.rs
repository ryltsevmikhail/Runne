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

fn assert_persisted_decision(
    database: &support::Database,
    approval_id: ApprovalId,
    context: &ApprovalCommandContext,
    decision: ApprovalDecision,
) {
    let connection =
        validated_reopen::open_validated_reader(database.file.path(), database.identity).unwrap();
    let actual = connection.query_row(
        "SELECT decision_command_id, decision_idempotency_key, decision_principal_id, decision, state, request_version FROM approvals WHERE approval_id = ?1",
        [approval_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).unwrap();
    let (stored_decision, state) = match decision {
        ApprovalDecision::Approve => (1, 2),
        ApprovalDecision::Deny => (2, 3),
    };
    assert_eq!(
        actual,
        (
            context.command_id.as_bytes().to_vec(),
            context.idempotency_key.as_str().to_owned(),
            context.principal.as_str().to_owned(),
            stored_decision,
            state,
            2,
        )
    );
}

async fn assert_decision_conflict(
    repository: &runne_store::ProjectWorkspaceStore,
    context: ApprovalCommandContext,
    command: ApprovalDecisionCommand,
) {
    assert_eq!(
        repository.decide_approval(context, command).await,
        Err(ApprovalHostError::Conflict)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn opposite_approval_decisions_conflict_and_preserve_the_first_decision() {
    for (case, (winner, opposite)) in [
        (ApprovalDecision::Approve, ApprovalDecision::Deny),
        (ApprovalDecision::Deny, ApprovalDecision::Approve),
    ]
    .into_iter()
    .enumerate()
    {
        let approval_id = ApprovalId::from_bytes(id(0x80 + case as u8));
        let database = support::Database::new("approval-opposite-decisions");
        let repository = database.repository();
        repository
            .create_pending_approval(create_command(approval_id, "execute"))
            .await
            .unwrap();

        let winner_context = context(0x90 + case as u8, "approval-winner");
        let winner_command = request_decision(approval_id, winner);
        let first_ack = repository
            .decide_approval(winner_context.clone(), winner_command.clone())
            .await
            .unwrap();
        let winner_state = match winner {
            ApprovalDecision::Approve => ApprovalState::Approved,
            ApprovalDecision::Deny => ApprovalState::Denied,
        };
        assert_eq!(
            (
                first_ack.approval_id(),
                first_ack.task_run_id(),
                first_ack.state(),
                first_ack.new_version()
            ),
            (
                approval_id,
                TaskRunId::from_bytes(id(0x71)),
                winner_state,
                2
            )
        );
        assert_decision_conflict(
            &repository,
            winner_context.clone(),
            request_decision(approval_id, opposite),
        )
        .await;
        assert_decision_conflict(
            &repository,
            context(0xa0 + case as u8, "approval-opposite-fresh"),
            request_decision(approval_id, opposite),
        )
        .await;
        for changed_binding in changed_binding_decisions(approval_id, winner) {
            assert_decision_conflict(&repository, winner_context.clone(), changed_binding).await;
        }

        let query_context = ApprovalQueryContext {
            principal: ApiPrincipalId::new("owner").unwrap(),
        };
        let before_replay = repository
            .get_approval(query_context.clone(), approval_id)
            .await
            .unwrap();
        assert_eq!(
            (before_replay.state(), before_replay.request_version()),
            (winner_state, 2)
        );
        assert_eq!(
            repository
                .decide_approval(winner_context.clone(), winner_command.clone())
                .await
                .unwrap(),
            first_ack
        );
        assert_eq!(
            repository
                .get_approval(query_context.clone(), approval_id)
                .await
                .unwrap(),
            before_replay
        );
        assert_persisted_decision(&database, approval_id, &winner_context, winner);

        drop(repository);
        let reopened_repository = database.reopen();
        assert_decision_conflict(
            &reopened_repository,
            context(0xb0 + case as u8, "approval-opposite-after-reopen"),
            request_decision(approval_id, opposite),
        )
        .await;
        for changed_binding in changed_binding_decisions(approval_id, winner) {
            assert_decision_conflict(
                &reopened_repository,
                winner_context.clone(),
                changed_binding,
            )
            .await;
        }
        assert_eq!(
            reopened_repository
                .get_approval(query_context.clone(), approval_id)
                .await
                .unwrap(),
            before_replay
        );
        assert_eq!(
            reopened_repository
                .decide_approval(winner_context.clone(), winner_command)
                .await
                .unwrap(),
            first_ack
        );
        assert_eq!(
            reopened_repository
                .get_approval(query_context, approval_id)
                .await
                .unwrap(),
            before_replay
        );
        assert_persisted_decision(&database, approval_id, &winner_context, winner);
    }
}
