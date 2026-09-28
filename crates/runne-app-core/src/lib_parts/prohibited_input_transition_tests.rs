use super::*;

#[tokio::test]
async fn prohibited_input_refusal_is_local_noncommitted_manual_without_receipt() {
    let (_directory, core) = v7_test_core();
    let conversation = CanonicalId::now_v7();
    let command_id = CanonicalId::now_v7();
    let key = command_id.to_string();
    let request = conversation_request(
        runne_local_store::MutationOperation::ConversationGenerateText,
        conversation,
        1,
        CanonicalMutationCommand::GenerateText {
            conversation_id: conversation,
            text: "clean input".into(),
        },
        CommandIdentity::new(command_id, key.clone()).expect("identity"),
        key,
    )
    .expect("request");
    let mut lease = core
        .prepare_mutation(request.clone())
        .await
        .expect("prepare");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::ProhibitedInputRejectedBeforeAdmission {
            timestamp: 2,
        },
    )
    .expect("refusal");
    assert_eq!(
        lease.anchored_record.disposition(),
        runne_local_store::ClientMutationDisposition::ManualResolution
    );
    assert_eq!(
        lease.anchored_record.runtime_disposition(),
        Some(runne_local_store::RuntimeCommitDisposition::NotCommittedRetryable)
    );
    assert!(lease.anchored_record.canonical_outcome().is_none());
    drop(lease);
    let reopened = core
        .prepare_mutation(request)
        .await
        .expect("reopen refusal");
    assert_eq!(
        reopened.anchored_record.disposition(),
        runne_local_store::ClientMutationDisposition::ManualResolution
    );
    assert!(matches!(
        core.dispatch_prepared_mutation(reopened).await,
        Err(AppCoreError::MutationUnavailable)
    ));
    let next_id = CanonicalId::now_v7();
    let next_key = next_id.to_string();
    let next_request = conversation_request(
        runne_local_store::MutationOperation::ConversationGenerateText,
        conversation,
        1,
        CanonicalMutationCommand::GenerateText {
            conversation_id: conversation,
            text: "edited clean input".into(),
        },
        CommandIdentity::new(next_id, next_key.clone()).expect("next identity"),
        next_key,
    )
    .expect("next request");
    assert_eq!(
        core.prepare_mutation(next_request)
            .await
            .expect("clean next intent")
            .anchored_record
            .disposition(),
        runne_local_store::ClientMutationDisposition::Prepared
    );
}

#[tokio::test]
async fn prohibited_refusal_transition_is_limited_to_first_generate_text_send() {
    let (_directory, core) = v7_test_core();
    let project = CanonicalId::now_v7();
    let mut project_lease = core
        .prepare_mutation(
            MutationRequest::create_project(project, "Project".into()).expect("request"),
        )
        .await
        .expect("prepare");
    core.transition_v7_under_operation(
        &mut project_lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    assert!(
        core.transition_v7_under_operation(
            &mut project_lease,
            runne_local_store::V7MutationTransition::ProhibitedInputRejectedBeforeAdmission {
                timestamp: 2
            }
        )
        .is_err()
    );

    let conversation = CanonicalId::now_v7();
    let command_id = CanonicalId::now_v7();
    let key = command_id.to_string();
    let request = conversation_request(
        runne_local_store::MutationOperation::ConversationGenerateText,
        conversation,
        1,
        CanonicalMutationCommand::GenerateText {
            conversation_id: conversation,
            text: "hello".into(),
        },
        CommandIdentity::new(command_id, key.clone()).expect("identity"),
        key,
    )
    .expect("request");
    let mut retried = core.prepare_mutation(request).await.expect("prepare");
    core.transition_v7_under_operation(
        &mut retried,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 3 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut retried,
        runne_local_store::V7MutationTransition::NotCommittedRetryable { timestamp: 4 },
    )
    .expect("first attempt classification");
    core.resend_v7_under_operation(&mut retried, 5)
        .expect("resend");
    assert!(
        core.transition_v7_under_operation(
            &mut retried,
            runne_local_store::V7MutationTransition::ProhibitedInputRejectedBeforeAdmission {
                timestamp: 6
            }
        )
        .is_err()
    );
}

#[tokio::test]
async fn prohibited_input_on_retry_resend_is_propagated_not_swallowed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // One-shot provider answer: the resent input is rejected pre-admission
    // with the exact closed 422 prohibited-secret envelope.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let request_id = "018f2e3a-7000-7000-8000-0000000003f0";
    let body = format!(r#"{{"code":"prohibited_secret_material","requestId":"{request_id}"}}"#);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("generate request");
        let mut bytes = [0; 4096];
        let _used = stream.read(&mut bytes).await.expect("read generate request");
        let reply = format!(
            "HTTP/1.1 422 test\r\nx-request-id: {request_id}\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).await.expect("reply");
    });
    let (_directory, core) = {
        let directory = tempfile::tempdir().expect("directory");
        let core = AppCore::open_with_mock_runtime(
            &directory.path().join("profile.sqlite3"),
            reconcile_client(&origin),
        )
        .expect("core");
        (directory, core)
    };
    let conversation = CanonicalId::now_v7();
    let command_id = CanonicalId::now_v7();
    let key = command_id.to_string();
    let request = conversation_request(
        runne_local_store::MutationOperation::ConversationGenerateText,
        conversation,
        1,
        CanonicalMutationCommand::GenerateText {
            conversation_id: conversation,
            text: "clean input".into(),
        },
        CommandIdentity::new(command_id, key.clone()).expect("identity"),
        key,
    )
    .expect("request");
    let mut lease = core.prepare_mutation(request).await.expect("prepare");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::NotCommittedRetryable { timestamp: 2 },
    )
    .expect("retryable");
    core.resend_v7_under_operation(&mut lease, 3).expect("resend");
    assert_eq!(lease.anchored_record.resend_count(), 1);
    // The refusal is no longer swallowed into a successful dispatch.
    assert!(matches!(
        core.send_or_classify_prohibited_input(&mut lease, false).await,
        Err(AppCoreError::ProhibitedInputRejected)
    ));
    // No ledger transition happened on the resend: the record stays
    // Dispatching with its recorded resend count.
    assert_eq!(
        lease.anchored_record.disposition(),
        runne_local_store::ClientMutationDisposition::Dispatching
    );
    assert_eq!(lease.anchored_record.resend_count(), 1);
    server.await.expect("prohibited server");
}
