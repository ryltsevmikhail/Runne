use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use super::*;

pub(super) fn local_submit(
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    key: &str,
    script: &str,
) -> runne_runtime_client::SubmitTaskRunRequest {
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), script.to_owned()],
        Vec::new(),
    )
    .expect("valid structured local command");
    runne_runtime_client::SubmitTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-mode-{key}"),
        )
        .unwrap(),
        conversation_id,
        workspace_id,
        format!("Run one local permission-mode effect {key}"),
    )
    .unwrap()
    .with_local_command(command)
    .unwrap()
}

pub(super) fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

pub(super) async fn wait_for_approval(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
) -> runne_runtime_client::ApprovalSummaryDto {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(approval) = client
            .list_pending_approvals()
            .await
            .expect("list local process approvals")
            .into_iter()
            .find(|approval| approval.task_run_id() == task)
        {
            return approval;
        }
        if tokio::time::Instant::now() >= deadline {
            let task_run = client.get_task_run(task).await.expect("public TaskRun");
            let state_reason = (task_run.state(), task_run.terminal_result());
            panic!("state+reason: {state_reason:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(super) async fn approve_exact(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) -> runne_runtime_client::ApprovalDecisionAcknowledgementDto {
    client
        .decide_approval(
            runne_runtime_client::ApprovalDecisionRequest::new(
                runne_runtime_client::CommandIdentity::new(
                    runne_runtime_client::CanonicalId::now_v7(),
                    format!("approve-local-mode-{}", approval.approval_id()),
                )
                .unwrap(),
                approval.approval_id(),
                approval.request_version(),
                runne_runtime_client::ApprovalDecisionDto::Approve,
                *approval.action_digest(),
                approval.policy_revision(),
                1,
            )
            .expect("exact local invocation approval"),
        )
        .await
        .expect("approve exact local invocation")
}

pub(super) async fn deny_exact(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) {
    let decision = runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("deny-local-mode-{}", approval.approval_id()),
        )
        .unwrap(),
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Deny,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("exact version-bound local-command denial");
    assert_eq!(
        client
            .decide_approval(decision)
            .await
            .expect("deny exact local-command approval through public API")
            .state(),
        runne_runtime_client::ApprovalStateDto::Denied
    );
}

pub(super) async fn assert_no_task_approval(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
) {
    assert!(
        client
            .list_pending_approvals()
            .await
            .expect("read pending local approvals")
            .iter()
            .all(|approval| approval.task_run_id() != task),
        "TaskRun has no pending human approval"
    );
}

pub(super) async fn assert_changed_intents_conflict(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    requests: &[runne_runtime_client::SubmitTaskRunRequest],
) {
    for (index, request) in requests.iter().enumerate() {
        let error = match client.submit_task_run(request.clone()).await {
            Ok(_) => panic!("changed local-command intent {index} was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            runne_runtime_client::RuntimeApiErrorKind::Conflict,
            "changed local-command intent {index} returns a stable conflict"
        );
    }
}

pub(super) async fn wait_for_terminal(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    task: runne_runtime_client::CanonicalId,
    first_effect: &Path,
    second_effect: &Path,
) -> runne_runtime_client::TaskRunSnapshot {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let current = client.get_task_run(task).await.expect("read local TaskRun");
        if matches!(
            current.state(),
            runne_runtime_client::TaskRunState::Succeeded
                | runne_runtime_client::TaskRunState::Failed
                | runne_runtime_client::TaskRunState::Cancelled
                | runne_runtime_client::TaskRunState::BudgetExhausted
                | runne_runtime_client::TaskRunState::PolicyDenied
                | runne_runtime_client::TaskRunState::Unrecoverable
        ) {
            return current;
        }
        if tokio::time::Instant::now() >= deadline {
            let local = client
                .get_task_run_effects(task)
                .await
                .map(|effects| {
                    effects
                        .local_command()
                        .map(|local| (local.outcome(), local.stop(), local.exit_code()))
                })
                .map_err(|error| error.kind());
            let durable = durable_local_diagnostic(database, task);
            let store_stage = local_store_diagnostic_stage(database);
            let runtime_root = database.parent().and_then(Path::parent);
            let local_preapproval_stage = runtime_root
                .map(crate::t1_startup_diagnostic::local_preapproval_diagnostic)
                .unwrap_or_else(|| "unrecognized".to_owned());
            let runtime_root_permissions_masked = runtime_root
                .and_then(|root| std::fs::metadata(root).ok())
                .map(|metadata| metadata.permissions().mode() & 0o077);
            panic!(
                "local TaskRun did not settle: state={:?}; terminal={:?}; local={local:?}; durable={durable:?}; store_stage={store_stage}; local_preapproval_stage={local_preapproval_stage}; runtime_root_permissions_masked_0o077={runtime_root_permissions_masked:?}; files=({}, {})",
                current.state(),
                current.terminal_result(),
                first_effect.exists(),
                second_effect.exists()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
