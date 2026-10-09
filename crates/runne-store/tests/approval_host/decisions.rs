use super::*;

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

pub(super) fn assert_persisted_decision(
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

pub(super) async fn assert_decision_conflict(
    repository: &runne_store::ProjectWorkspaceStore,
    context: ApprovalCommandContext,
    command: ApprovalDecisionCommand,
) {
    assert_eq!(
        repository.decide_approval(context, command).await,
        Err(ApprovalHostError::Conflict)
    );
}
