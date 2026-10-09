use std::path::Path;
use std::time::Duration;

use super::*;

pub(super) struct LocalNoEffectCase {
    task: runne_runtime_client::CanonicalId,
    version: u64,
    before: std::path::PathBuf,
    after: std::path::PathBuf,
    mode_change: bool,
}

pub(super) enum LocalNoEffectResolution<'a> {
    Deny,
    Expire,
    ChangeMode(&'a mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor),
}

pub(super) async fn exercise_local_no_effect_case(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    resolution: LocalNoEffectResolution<'_>,
) -> LocalNoEffectCase {
    let mode_change = matches!(&resolution, LocalNoEffectResolution::ChangeMode(_));
    let listener = LoopbackCapture::new();
    let tag = format!(
        "local-mode-{}-{}",
        match &resolution {
            LocalNoEffectResolution::Deny => "denied",
            LocalNoEffectResolution::Expire => "expired",
            LocalNoEffectResolution::ChangeMode(_) => "mode-changed",
        },
        uuid::Uuid::now_v7()
    );
    let before = project_directory.join(format!("{tag}-before-network"));
    let after = project_directory.join(format!("{tag}-after-network"));
    let script = format!(
        "printf '%s\\n' '{tag}' >> '{}'; exec 3<>/dev/tcp/127.0.0.1/{} 2>/dev/null || exit 42; printf '%s\\n' '{tag}' >&3; exec 3>&-; printf '%s\\n' after >> '{}'",
        before.display(),
        listener.port,
        after.display()
    );
    let task = client
        .submit_task_run(local_submit(conversation_id, workspace_id, &tag, &script))
        .await
        .expect("submit local command awaiting a public approval decision")
        .task_run_id();
    let approval = wait_for_approval(client, task).await;
    assert_eq!(approval.action(), "local_command.execute");
    assert!(!before.exists() && !after.exists());
    match resolution {
        LocalNoEffectResolution::Deny => deny_exact(client, &approval).await,
        LocalNoEffectResolution::Expire => expire_exact(client, &approval).await,
        LocalNoEffectResolution::ChangeMode(supervisor) => {
            assert_eq!(
                client
                    .permission_mode_status(workspace_id)
                    .await
                    .expect("read Risk Based mode while exact process approval is pending")
                    .selected_mode,
                runne_api::PermissionModeV1::RiskBased
            );
            crate::t1_local_only::change_local_permission_mode(
                client,
                workspace_id,
                supervisor,
                runne_api::PermissionModeV1::AskAlways,
            )
            .await;
            let acknowledgement = approve_exact(client, &approval).await;
            assert_eq!(
                acknowledgement.state(),
                runne_runtime_client::ApprovalStateDto::Approved,
                "mode change preserves the exact pending approval as an auditable stale record"
            );
            assert_eq!(
                client
                    .get_approval(approval.approval_id())
                    .await
                    .expect("read accepted exact approval after mode change")
                    .state(),
                runne_runtime_client::ApprovalStateDto::Approved
            );
        }
    }

    let terminal = wait_for_terminal(client, database, task, &before, &after).await;
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read public no-effect projection");
    assert_eq!(
        effects
            .local_command()
            .expect("no-effect local-command outcome")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        local_no_effect_release_facts(database, task)
            .expect("read-only exact no-effect release evidence"),
        ("no_effect_terminal".to_owned(), true, 1, 1, 0, 0),
        "one canonical capture and released absent-dispatch receipt, with no legacy approval authority, spent row, or dispatch row"
    );
    if mode_change {
        assert_eq!(
            local_permission_stop_facts(database, task)
                .expect("read exact local mode-change stop reason"),
            (1, Some(2)),
            "canonical Ask Always selection change stops the captured Risk Based admission"
        );
    }
    assert!(!before.exists() && !after.exists());
    assert!(listener.finish().is_empty());
    assert_no_task_approval(client, task).await;
    LocalNoEffectCase {
        task,
        version: terminal.stream_version(),
        before,
        after,
        mode_change,
    }
}

async fn expire_exact(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) {
    let expiry = u64::try_from(approval.expires_at()).expect("positive local approval expiry");
    let now = unix_millis();
    assert!(expiry > now, "local approval is genuinely pending");
    assert!(
        expiry - now <= 120_000,
        "local approval has its bounded lifetime"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(130);
    while unix_millis() <= expiry {
        assert!(
            tokio::time::Instant::now() < deadline,
            "approval did not expire"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let expired = client
        .get_approval(approval.approval_id())
        .await
        .expect("read expired local command approval");
    assert_eq!(
        expired.state(),
        runne_runtime_client::ApprovalStateDto::Expired
    );
    let late = runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("late-approve-local-mode-{}", approval.approval_id()),
        )
        .expect("late approval identity"),
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Approve,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("late exact approval request");
    assert!(
        client.decide_approval(late).await.is_err(),
        "expired approval cannot be revived"
    );
    let still_expired = client
        .get_approval(approval.approval_id())
        .await
        .expect("read approval after rejected late decision");
    assert_eq!(
        still_expired.state(),
        runne_runtime_client::ApprovalStateDto::Expired
    );
}

pub(super) async fn assert_reopened_no_effect_case(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    case: &LocalNoEffectCase,
    label: &str,
) {
    let task = client
        .get_task_run(case.task)
        .await
        .expect("read no-effect TaskRun after same-root reopen");
    assert_eq!(task.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(task.stream_version(), case.version);
    assert_eq!(task.terminal_result(), None);
    assert_eq!(
        client
            .get_task_run_effects(case.task)
            .await
            .expect("read retained no-effect local projection after reopen")
            .local_command()
            .expect("retained no-effect local command")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert!(
        !case.before.exists() && !case.after.exists(),
        "{label} process leaves no files after reopen"
    );
    assert_eq!(
        local_no_effect_release_facts(database, case.task)
            .expect("re-read exact no-effect release evidence after reopen"),
        ("no_effect_terminal".to_owned(), true, 1, 1, 0, 0),
        "same no-effect proof persists with no legacy approval authority after reopen"
    );
    if case.mode_change {
        assert_eq!(
            local_permission_stop_facts(database, case.task)
                .expect("re-read exact mode-change stop reason after reopen"),
            (1, Some(2)),
            "reason 2 no-effect settlement persists across reopen"
        );
    }
}
