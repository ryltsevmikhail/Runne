fn submit_request() -> MutationRequest {
    MutationRequest::submit_task_run(
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("conversation"),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").expect("workspace"),
        "Summarize the project status".to_owned(),
    )
    .expect("request")
}

async fn read_submit_request(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut bytes = [0; 8192];
    let count = stream.read(&mut bytes).await.expect("request");
    String::from_utf8(bytes[..count].to_vec()).expect("request text")
}

async fn write_submit_reconciliation(stream: &mut tokio::net::TcpStream, task_run: &str) {
    use tokio::io::AsyncWriteExt;
    let body = format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"submit_task_run","taskRunId":"{task_run}","newVersion":2}}}}"#
    );
    stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("reconciliation");
}

#[test]
fn submit_request_anchors_both_conversation_and_workspace_bindings() {
    let request = submit_request();
    assert_eq!(
        request.operation,
        runne_local_store::MutationOperation::TaskRunSubmit
    );
    assert_eq!(
        request.target.kind(),
        runne_local_store::MutationTargetKind::Conversation
    );
    assert_eq!(request.expected_version, 0);
    assert!(request.validate_invariants().is_ok());
    assert!(!format!("{request:?}").contains("Summarize the project status"));
    assert!(
        !format!("{:?}", request.ledger_command().expect("ledger command"))
            .contains("Summarize the project status")
    );
    assert_eq!(
        request.ledger_command().expect("ledger command"),
        runne_local_store::NormalizedMutationCommand::SubmitTaskRun {
            conversation_id: runne_local_store::BoundedCanonicalId::parse(
                b"018f2e3a-7000-7000-8000-000000000901"
            )
            .expect("conversation"),
            workspace_id: runne_local_store::BoundedCanonicalId::parse(
                b"018f2e3a-7000-7000-8000-000000000902"
            )
            .expect("workspace"),
            prompt: "Summarize the project status".to_owned(),
        }
    );
}

#[test]
fn submit_prompt_must_be_nonempty_and_within_the_message_bound() {
    let conversation = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").unwrap();
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").unwrap();
    assert!(MutationRequest::submit_task_run(conversation, workspace, String::new()).is_err());
    assert!(MutationRequest::submit_task_run(conversation, workspace, " \t\n".to_owned()).is_err());
    assert!(
        MutationRequest::submit_task_run(conversation, workspace, "x".repeat(64 * 1024 + 1))
            .is_err()
    );
}

#[tokio::test]
async fn whitespace_submit_is_rejected_before_ledger_preparation() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let conversation =
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("conversation");
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").expect("workspace");

    assert!(matches!(
        core.submit_task_run(conversation, workspace, " \t\n".to_owned())
            .await,
        Err(AppCoreError::InvalidMutation)
    ));
    assert!(
        core.recover_anchored_mutations_v7()
            .await
            .expect("read empty ledger")
            .is_empty()
    );
}

#[tokio::test]
async fn duplicate_submit_identity_reuses_ledger_entry_and_changed_binding_conflicts() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let request = submit_request();
    let duplicate = request.clone();
    let first = core
        .prepare_mutation(request.clone())
        .await
        .expect("first prepare");
    let replay = core
        .prepare_mutation(duplicate)
        .await
        .expect("duplicate prepare");
    assert_eq!(
        first.anchored_record.idempotency_key(),
        replay.anchored_record.idempotency_key()
    );
    let mut changed = request.clone();
    let CanonicalMutationCommand::SubmitTaskRun {
        conversation_id, ..
    } = changed.semantic_command
    else {
        unreachable!()
    };
    changed.semantic_command = CanonicalMutationCommand::SubmitTaskRun {
        conversation_id,
        workspace_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000903")
            .expect("other workspace"),
        prompt: Some("Summarize the project status".to_owned()),
    };
    assert!(matches!(
        core.prepare_mutation(changed).await,
        Err(AppCoreError::MutationUnavailable)
    ));
    let mut changed_prompt = submit_request();
    changed_prompt.command_identity = request.command_identity.clone();
    changed_prompt.idempotency_key = request.idempotency_key.clone();
    changed_prompt.semantic_command = CanonicalMutationCommand::SubmitTaskRun {
        conversation_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901")
            .expect("conversation"),
        workspace_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902")
            .expect("workspace"),
        prompt: Some("A different prompt".to_owned()),
    };
    assert!(matches!(
        core.prepare_mutation(changed_prompt).await,
        Err(AppCoreError::MutationUnavailable)
    ));
}

include!("mutation_submit_tests/reconciliation.rs");
