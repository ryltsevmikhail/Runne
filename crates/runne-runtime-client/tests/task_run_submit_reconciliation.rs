use runne_runtime_client::{
    CommandReconciliationOutcome, CommandReconciliationRequest, SubmitTaskRunRequest,
    mock_authenticated_runtime_client,
};
#[path = "support/task_run_submit_reconciliation.rs"]
mod support;
use support::*;

#[tokio::test]
async fn prompt_reconciliation_serializes_exact_input_and_redacts_debug() {
    let request = CommandReconciliationRequest::submit_task_run(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
        "private prompt",
    )
    .expect("valid prompt");
    assert!(!format!("{request:?}").contains("private prompt"));
    let (origin, server) = serve(
        response_body(),
        format!(
            r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","prompt":"private prompt"}}"#
        ),
    )
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let outcome = client.reconcile_command(request).await.unwrap();
    assert!(matches!(
        outcome,
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn historical_promptless_reconciliation_keeps_the_legacy_payload() {
    let request = CommandReconciliationRequest::submit_task_run_legacy(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
    );
    let (origin, server) = serve(
        response_body(),
        format!(
            r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}"}}"#
        ),
    )
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let outcome = client.reconcile_command(request).await.unwrap();
    assert!(matches!(
        outcome,
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn submit_request_reconciliation_preserves_model_and_selected_profile_together() {
    let profile = runne_api::SelectedProviderProfile::new(
        "gocode-openai-responses-background-text/1".into(),
        [0xaa; 32],
    )
    .unwrap();
    let submit = SubmitTaskRunRequest::new(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
        "private prompt",
    )
    .unwrap()
    .with_model("provider/model-v2")
    .unwrap()
    .with_selected_profile(profile)
    .unwrap();
    let request = CommandReconciliationRequest::submit_task_run_from_request(&submit).unwrap();
    let (origin, server) = serve(
        response_body(),
        format!(
            r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","prompt":"private prompt","model":"provider/model-v2","profile":{{"profileId":"gocode-openai-responses-background-text/1","profileDigest":"{}"}}}}"#,
            "aa".repeat(32)
        ),
    )
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    assert!(matches!(
        client.reconcile_command(request).await.unwrap(),
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn submit_request_reconciliation_preserves_profile_only_selection() {
    let profile = runne_api::SelectedProviderProfile::new(
        "gocode-openai-responses-background-text/1".into(),
        [0xbb; 32],
    )
    .unwrap();
    let submit = SubmitTaskRunRequest::new(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
        "private prompt",
    )
    .unwrap()
    .with_selected_profile(profile)
    .unwrap();
    let request = CommandReconciliationRequest::submit_task_run_from_request(&submit).unwrap();
    let (origin, server) = serve(
        response_body(),
        format!(
            r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","prompt":"private prompt","profile":{{"profileId":"gocode-openai-responses-background-text/1","profileDigest":"{}"}}}}"#,
            "bb".repeat(32)
        ),
    )
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    assert!(matches!(
        client.reconcile_command(request).await.unwrap(),
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn local_command_reconciliation_preserves_exact_typed_intent() {
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        "tools".into(),
        vec!["sh".into(), "-c".into(), "printf safe".into()],
        vec![("Z".into(), "last".into()), ("A".into(), "first".into())],
    )
    .unwrap();
    let submit = SubmitTaskRunRequest::new(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
        "description only",
    )
    .unwrap()
    .with_local_command(command)
    .unwrap();
    let request = CommandReconciliationRequest::submit_task_run_from_request(&submit).unwrap();
    let expected = format!(
        r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","prompt":"description only","localCommand":{{"executable":{{"kind":"system_program","value":"shell"}},"cwd":"tools","argv":["sh","-c","printf safe"],"env":[{{"key":"A","value":"first"}},{{"key":"Z","value":"last"}}]}}}}"#
    );
    let (origin, server) = serve(response_body(), expected).await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    assert!(matches!(
        client.reconcile_command(request).await.unwrap(),
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

#[test]
fn changed_local_command_produces_a_different_reconciliation_witness() {
    let build = |arg: &str| {
        SubmitTaskRunRequest::new(identity(), id(CONVERSATION), id(WORKSPACE), "description")
            .unwrap()
            .with_local_command(
                runne_api::TaskRunLocalCommand::new(
                    runne_api::TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
                    ".".into(),
                    vec!["tool".into(), arg.into()],
                    vec![],
                )
                .unwrap(),
            )
            .unwrap()
    };
    let left =
        CommandReconciliationRequest::submit_task_run_from_request(&build("--same")).unwrap();
    let retry =
        CommandReconciliationRequest::submit_task_run_from_request(&build("--same")).unwrap();
    let changed =
        CommandReconciliationRequest::submit_task_run_from_request(&build("--changed")).unwrap();
    assert_eq!(
        left, retry,
        "lost-ack replay carries the same structured command"
    );
    assert_ne!(
        left, changed,
        "changed command cannot reconcile as the same submit"
    );
}

#[test]
fn submit_request_rejects_model_or_profile_added_after_local_command() {
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let local =
        SubmitTaskRunRequest::new(identity(), id(CONVERSATION), id(WORKSPACE), "description")
            .unwrap()
            .with_local_command(command)
            .unwrap();
    assert!(local.clone().with_model("model").is_err());
    let profile = runne_api::SelectedProviderProfile::new("profile".into(), [0xcc; 32]).unwrap();
    assert!(local.with_selected_profile(profile).is_err());
}

#[test]
fn submit_request_reconciliation_rejects_invalid_model() {
    let submit = SubmitTaskRunRequest::new(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
        "private prompt",
    )
    .unwrap()
    .with_model("invalid model")
    .unwrap();
    assert!(CommandReconciliationRequest::submit_task_run_from_request(&submit).is_err());
}

#[tokio::test]
async fn explicit_model_reconciliation_serializes_the_exact_model() {
    let request = CommandReconciliationRequest::submit_task_run_with_model(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
        "private prompt",
        "provider/model-v2",
    )
    .expect("valid explicit model");
    let (origin, server) = serve(
        response_body(),
        format!(
            r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","prompt":"private prompt","model":"provider/model-v2"}}"#
        ),
    )
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    assert!(matches!(
        client.reconcile_command(request).await.unwrap(),
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

#[test]
fn explicit_model_reconciliation_rejects_invalid_model() {
    assert!(
        CommandReconciliationRequest::submit_task_run_with_model(
            identity(),
            id(CONVERSATION),
            id(WORKSPACE),
            "prompt",
            "bad model",
        )
        .is_err()
    );
}
