// Closed-surface pins: exact ack validation, duplicate identity behaviour,
// capability profile membership, and the absence of runtime-owned transitions
// from the client surface.

#[tokio::test]
async fn submit_rejects_wrong_transition_version_or_extra_identity() {
    // Wrong transition, wrong version, attempt-bound and terminal-bound acks
    // must all fail closed as InvalidResponse.
    for body in [
        submit_ack_body(TASK_RUN_ID, 2, "queued"),
        submit_ack_body(TASK_RUN_ID, 0, "submitted"),
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":2,\"transition\":\"submitted\",\"attemptId\":\"{TASK_RUN_ID}\",\"terminalResult\":null}}"
        ),
        "{{\"taskRunId\":\"TASK_RUN_ID\",\"streamVersion\":2,\"transition\":\"submitted\",\"attemptId\":null,\"terminalResult\":{\"type\":\"success\"}}}"
            .replace("TASK_RUN_ID", TASK_RUN_ID),
    ] {
        let server = serve(vec![response(202, "Accepted", &body)]).await;
        let client = mock_authenticated_runtime_client(server.origin(), session()).expect("client");
        let outcome = client
            .submit_task_run(SubmitTaskRunRequest::new(
                identity(COMMAND_ID, "reject-submit"),
                conversation_id(),
                workspace_id(),
            ))
            .await;
        assert_eq!(
            outcome.expect_err("ack must be rejected").kind(),
            RuntimeApiErrorKind::InvalidResponse,
            "body: {body}"
        );
        let _ = server.finish().await;
    }
}

#[tokio::test]
async fn duplicate_identity_resends_the_identical_payload() {
    let ack = response(202, "Accepted", &submit_ack_body(TASK_RUN_ID, 2, "submitted"));
    let server = serve(vec![ack.clone(), ack]).await;
    let client = mock_authenticated_runtime_client(server.origin(), session()).expect("client");
    let request = SubmitTaskRunRequest::new(
        identity(COMMAND_ID, "lifecycle-duplicate"),
        conversation_id(),
        workspace_id(),
    );
    let first = client.submit_task_run(request.clone()).await.expect("first");
    let duplicate = client.submit_task_run(request).await.expect("duplicate");
    assert_eq!(first, duplicate, "same identity and payload, one receipt shape");
    let requests = server.finish().await;
    assert!(requests[0].contains("idempotency-key: lifecycle-duplicate"));
    assert_eq!(requests[0], requests[1], "duplicate resends the identical payload");
}

#[tokio::test]
async fn get_rejects_snapshot_identity_or_shape_mismatch() {
    // Wrong aggregate ID in the snapshot body.
    let foreign = snapshot_body("queued", 2, false)
        .replace(TASK_RUN_ID, "018f2e3a-7000-7000-8000-0000000002af");
    let server = serve(vec![response(200, "OK", &foreign)]).await;
    let client = mock_authenticated_runtime_client(server.origin(), session()).expect("client");
    assert_eq!(
        client
            .get_task_run(task_run_id())
            .await
            .expect_err("foreign snapshot must be rejected")
            .kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
    server.finish().await;

    // Terminal result on a non-terminal state.
    let server = serve(vec![response(200, "OK", &snapshot_body("queued", 2, true))]).await;
    let client = mock_authenticated_runtime_client(server.origin(), session()).expect("client");
    assert_eq!(
        client
            .get_task_run(task_run_id())
            .await
            .expect_err("terminal state on queued must be rejected")
            .kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
    server.finish().await;
}

#[tokio::test]
async fn cancel_rejects_non_cancellation_transitions() {
    let server = serve(vec![response(
        202,
        "Accepted",
        &submit_ack_body(TASK_RUN_ID, 3, "submitted"),
    )])
    .await;
    let client = mock_authenticated_runtime_client(server.origin(), session()).expect("client");
    assert_eq!(
        client
            .cancel_task_run(CancelTaskRunRequest::new(
                identity(CANCEL_COMMAND_ID, "reject-cancel"),
                task_run_id(),
                2,
            ))
            .await
            .expect_err("submit transition on cancel must be rejected")
            .kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
    server.finish().await;
}

/// Capability-profile pin: the client profile grants exactly the submit/get/
/// cancel `TaskRun` family and never a runtime-owned transition. Together with
/// `public_surface_signature_pin` (compile-time absence of the corresponding
/// methods) this proves the client cannot attempt queue/admit/start/complete.
#[test]
fn client_capability_profile_excludes_runtime_owned_transitions() {
    for capability in [
        "task_run.submit.v1",
        "task_run.get.v1",
        "task_run.cancel.v1",
    ] {
        assert!(
            REQUIRED_RUNTIME_CAPABILITIES.contains(&capability),
            "{capability} must stay in the required client profile"
        );
    }
    for forbidden in [
        "task_run.queue.v1",
        "task_run.admit.v1",
        "task_run.start.v1",
        "task_run.complete.v1",
    ] {
        assert!(
            !REQUIRED_RUNTIME_CAPABILITIES.contains(&forbidden),
            "{forbidden} must never be granted to clients"
        );
    }
}

/// Compile-time pin that the four public methods exist with their exact
/// request/acknowledgement types. Runtime-owned transitions (queue/admit/
/// start/complete) have no public surface to name here at all.
#[allow(dead_code, reason = "signature pin, never invoked")]
async fn public_surface_signature_pin(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
) {
    let _ = client.get_task_run(task_run_id()).await;
    let _ = client.list_task_runs().await;
    let _ = client
        .cancel_task_run(CancelTaskRunRequest::new(
            identity(CANCEL_COMMAND_ID, "pin"),
            task_run_id(),
            2,
        ))
        .await;
    let _ = client
        .submit_task_run(SubmitTaskRunRequest::new(
            identity(COMMAND_ID, "pin"),
            conversation_id(),
            workspace_id(),
        ))
        .await;
}
