fn v7_test_core() -> (tempfile::TempDir, AppCore) {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-v7", "lineage-v7", 1),
    )
    .expect("core");
    (directory, core)
}

fn project_outcome(id: CanonicalId) -> runne_local_store::CanonicalMutationOutcome {
    runne_local_store::CanonicalMutationOutcome::ProjectCreate {
        project_id: runne_local_store::BoundedCanonicalId::parse(id.to_string().as_bytes())
            .expect("id"),
        new_version: 1,
    }
}


#[tokio::test]
async fn v7_helpers_apply_only_closed_transitions_and_one_resend() {
    let (_directory, core) = v7_test_core();
    let project = CanonicalId::now_v7();
    let mut lease = core
        .prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("request"))
        .await
        .expect("prepare");

    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    assert_eq!(lease.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::Dispatching);
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::NotCommittedRetryable { timestamp: 2 },
    )
    .expect("retryable");
    assert_eq!(lease.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::Retryable);
    core.resend_v7_under_operation(&mut lease, 3).expect("resend");
    assert_eq!(lease.anchored_record.resend_count(), 1);
    assert!(core.resend_v7_under_operation(&mut lease, 4).is_err());

    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Observing { timestamp: 5 },
    )
    .expect("observing");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::CanonicalOutcome {
            outcome: Box::new(project_outcome(project)),
            summary: "durably_recorded".into(),
            timestamp: 6,
        },
    )
    .expect("canonical");
    assert_eq!(lease.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::CanonicalOutcome);
}

#[tokio::test]
async fn v7_helpers_keep_indeterminate_and_conflict_fail_closed() {
    let (_directory, core) = v7_test_core();
    let mut lease = core
        .prepare_mutation(MutationRequest::create_project(CanonicalId::now_v7(), "Project".into()).expect("request"))
        .await
        .expect("prepare");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 },
    )
    .expect("indeterminate");
    assert_eq!(lease.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::Reconciling);
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::ManualResolution {
            summary: "conflict".into(),
            timestamp: 3,
        },
    )
    .expect("manual");
    assert_eq!(lease.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::ManualResolution);
}

#[tokio::test]
async fn v7_helpers_reconcile_observing_without_a_generic_resend() {
    let (_directory, core) = v7_test_core();
    let project = CanonicalId::now_v7();
    let mut lease = core
        .prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("request"))
        .await
        .expect("prepare");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Observing { timestamp: 2 },
    )
    .expect("observing");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Indeterminate { timestamp: 3 },
    )
    .expect("reconciling");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::NotCommittedRetryable { timestamp: 4 },
    )
    .expect("retryable");
    assert_eq!(lease.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::Retryable);
    core.resend_v7_under_operation(&mut lease, 5).expect("dedicated resend");
    assert_eq!(lease.anchored_record.resend_count(), 1);
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Observing { timestamp: 6 },
    )
    .expect("observing after resend");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::CanonicalOutcome {
            outcome: Box::new(project_outcome(project)),
            summary: "durably_recorded".into(),
            timestamp: 7,
        },
    )
    .expect("canonical");
}

#[tokio::test]
async fn v7_transition_rejects_a_caller_request_that_differs_from_anchored_command() {
    let (_directory, core) = v7_test_core();
    let mut lease = core
        .prepare_mutation(MutationRequest::create_project(CanonicalId::now_v7(), "Project".into()).expect("request"))
        .await
        .expect("prepare");
    lease.request = MutationRequest::create_project(CanonicalId::now_v7(), "Changed".into()).expect("request");
    assert!(core
        .transition_v7_under_operation(
            &mut lease,
            runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .is_err());
}

#[tokio::test]
async fn dispatch_persists_only_the_typed_durable_reconciliation_outcome() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::now_v7();
    let server = tokio::spawn(async move {
        for (path, status, body) in [
            ("/v1/projects", 202, format!(r#"{{"projectId":"{project}","newVersion":1}}"#)),
            ("/v1/commands/reconcile", 200, format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#)),
        ] {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut request = [0; 4096];
            let count = stream.read(&mut request).await.expect("read");
            assert!(String::from_utf8_lossy(&request[..count]).contains(path));
            let response = format!("HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            stream.write_all(response.as_bytes()).await.expect("response");
        }
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        reconcile_client(&origin),
    )
    .expect("core");
    let lease = core
        .prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("request"))
        .await
        .expect("prepare");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Ok(MutationDispatchResult::Project(_))));
    server.await.expect("server");
}

#[test]
fn rejected_generation_terminals_keep_distinct_app_core_errors() {
    let rejection = runne_runtime_client::ConversationTextRejection {
        conversation_id: CanonicalId::now_v7(), task_run_id: CanonicalId::now_v7(),
        attempt_id: CanonicalId::now_v7(), conversation_stream_version: 3,
        task_run_stream_version: 5,
        user_message: runne_runtime_client::ConversationMessage {
            message_id: CanonicalId::now_v7(), role: runne_runtime_client::ConversationMessageRole::User,
            task_run_id: CanonicalId::now_v7(), attempt_id: CanonicalId::now_v7(), text: "hello".into(), committed_at: 1,
        },
        reserved_assistant_message_id: CanonicalId::now_v7(),
        reason: runne_runtime_client::ConversationGenerationFailureReason::ProviderOutputRejected,
    };
    assert!(matches!(
        AppCore::project_reconciled_result(&runne_runtime_client::CommandReconciliationOutcome::ConversationTextRejected(Box::new(rejection.clone()))),
        Err(AppCoreError::GenerationRejected)
    ));
    assert!(matches!(
        AppCore::project_reconciled_result(&runne_runtime_client::CommandReconciliationOutcome::ConversationTextProhibitedInputRejected(Box::new(rejection))),
        Err(AppCoreError::ProhibitedInputRejected)
    ));
}

fn reconcile_identity() -> CommandIdentity {
    CommandIdentity::new(CanonicalId::now_v7(), CanonicalId::now_v7().to_string()).expect("identity")
}

fn reconcile_client(origin: &str) -> runne_runtime_client::AuthenticatedRuntimeClient {
    runne_runtime_client::mock_authenticated_runtime_client(
        origin,
        runne_runtime_client::RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".into(),
            schema_hash: runne_runtime_client::GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities: runne_runtime_client::REQUIRED_RUNTIME_CAPABILITIES.iter().map(ToString::to_string).collect(),
            authority_id: "authority-v7".into(), principal_id: "principal".into(),
            event_log_lineage_id: "lineage-v7".into(), daemon_instance_id: "daemon".into(),
            launch_generation: 1, session_id: "session".into(), authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(), certificate_sha256: "11".repeat(32),
            capability_digest: "22".repeat(32),
        },
    )
    .expect("client")
}

async fn reconcile_outcome(
    request: runne_runtime_client::CommandReconciliationRequest,
    body: String,
) -> runne_runtime_client::CommandReconciliationOutcome {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.expect("read") > 0);
        let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        stream.write_all(response.as_bytes()).await.expect("response");
    });
    let runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(outcome) = reconcile_client(&origin)
        .reconcile_command(request)
        .await
        .expect("reconcile")
    else { panic!("durable outcome") };
    server.await.expect("server");
    outcome
}

#[tokio::test]
async fn converts_every_typed_reconciliation_outcome_and_rejects_mismatch() {
    use runne_local_store::NormalizedMutationCommand as Command;
    use runne_runtime_client::CommandReconciliationRequest as Request;
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("project");
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").expect("workspace");
    let conversation = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000903").expect("conversation");
    let task = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000904").expect("task");
    let attempt = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000905").expect("attempt");
    let user = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000906").expect("user");
    let assistant = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000907").expect("assistant");
    let id = |value: CanonicalId| runne_local_store::BoundedCanonicalId::parse(value.to_string().as_bytes()).expect("id");
    let text_body = |terminal: &str, tail: String| format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"generate_conversation_text","terminal":"{terminal}","conversationId":"{conversation}","taskRunId":"{task}","attemptId":"{attempt}","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"{user}","role":"user","taskRunId":"{task}","attemptId":"{attempt}","text":"hello","committedAt":1}}{tail}}}}}"#
    );
    let cases = vec![
        (Command::create_project(id(project), "Project".into()).expect("command"), Request::create_project(reconcile_identity(), project, "Project").expect("request"), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#)),
        (Command::ArchiveProject { project_id: id(project), expected_version: 1 }, Request::archive_project(reconcile_identity(), project, 1).expect("request"), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"archive_project","projectId":"{project}","newVersion":2}}}}"#)),
        (Command::DeleteProject { project_id: id(project), expected_version: 1 }, Request::delete_project(reconcile_identity(), project, 1).expect("request"), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"delete_project","projectId":"{project}","newVersion":2}}}}"#)),
        (Command::CreateWorkspace { workspace_id: id(workspace), project_id: id(project), display_name: "Workspace".into() }, Request::create_workspace(reconcile_identity(), workspace, project, "Workspace").expect("request"), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_workspace","workspaceId":"{workspace}","newVersion":1}}}}"#)),
        (Command::bind_workspace_root(id(workspace), 1, [9; 32]).expect("command"), Request::bind_workspace_root(reconcile_identity(), workspace, 1, "09".repeat(32)).expect("request"), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"bind_workspace_root","workspaceId":"{workspace}","newVersion":2}}}}"#)),
        (Command::OpenWorkspace { workspace_id: id(workspace), expected_version: 1 }, Request::open_workspace(reconcile_identity(), workspace, 1).expect("request"), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"open_workspace","workspaceId":"{workspace}","newVersion":2}}}}"#)),
        (Command::CreateConversation { conversation_id: id(conversation), workspace_id: id(workspace) }, Request::create_conversation(reconcile_identity(), conversation, workspace), format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_conversation","conversationId":"{conversation}","workspaceId":"{workspace}","streamVersion":1,"committedAt":1}}}}"#)),
        (Command::GenerateText { conversation_id: id(conversation), expected_version: 1, text: "hello".into() }, Request::generate_conversation_text(reconcile_identity(), conversation, 1, "hello").expect("request"), text_body("completed", format!(r#","assistantMessage":{{"messageId":"{assistant}","role":"assistant","taskRunId":"{task}","attemptId":"{attempt}","text":"answer","committedAt":2}}"#))),
        (Command::GenerateText { conversation_id: id(conversation), expected_version: 1, text: "hello".into() }, Request::generate_conversation_text(reconcile_identity(), conversation, 1, "hello").expect("request"), text_body("rejected", format!(r#","reservedAssistantMessageId":"{assistant}","reason":"provider_output_rejected""#))),
        (Command::GenerateText { conversation_id: id(conversation), expected_version: 1, text: "hello".into() }, Request::generate_conversation_text(reconcile_identity(), conversation, 1, "hello").expect("request"), text_body("prohibited_input_rejected", format!(r#","reservedAssistantMessageId":"{assistant}","reason":"provider_output_rejected""#))),
    ];
    for (command, request, body) in cases {
        let outcome = reconcile_outcome(request, body).await;
        let ledger = reconciliation_outcome_to_ledger(&command, &outcome).expect("conversion");
        assert!(ledger.correlates_to_command(&command));
    }
    let outcome = reconcile_outcome(
        Request::create_project(reconcile_identity(), project, "Project").expect("request"),
        format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#),
    )
    .await;
    let mismatch = Command::ArchiveProject { project_id: id(project), expected_version: 1 };
    assert!(reconciliation_outcome_to_ledger(&mismatch, &outcome).is_err());
}
