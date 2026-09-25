#[tokio::test]
async fn prompted_submit_fails_closed_for_nonexact_profile_or_capability() {
    let make_request = || {
        SubmitTaskRunRequest::new(
            identity(COMMAND_ID, "profile-gate"),
            id(CONVERSATION_ID),
            id(WORKSPACE_ID),
            "safe prompt",
        )
        .expect("valid request")
    };
    let mut invalid_sessions = Vec::new();
    let mut wrong_profile = session();
    wrong_profile.profile_id = "gocode-ui-client/2".to_owned();
    invalid_sessions.push(wrong_profile);
    let mut wrong_schema = session();
    wrong_schema.schema_hash = "not-the-profile-3-hash".to_owned();
    invalid_sessions.push(wrong_schema);
    let mut wrong_digest = session();
    wrong_digest.capability_digest = "00".repeat(32);
    invalid_sessions.push(wrong_digest);
    let mut missing_v2 = session();
    missing_v2
        .capabilities
        .retain(|item| item != "task_run.submit.v2");
    missing_v2.capability_digest = capability_digest(&missing_v2.capabilities);
    invalid_sessions.push(missing_v2);

    for rejected in invalid_sessions {
        let client = mock_authenticated_runtime_client("http://127.0.0.1:1", rejected)
            .expect("mock client construction is not a profile handshake");
        assert_eq!(
            client
                .submit_task_run(make_request())
                .await
                .expect_err("profile rejected")
                .kind(),
            RuntimeApiErrorKind::Incompatible
        );
    }
}

#[test]
fn client_task_run_capabilities_are_bounded_to_submit_get_cancel() {
    for capability in [
        "task_run.submit.v1",
        "task_run.submit.v2",
        "task_run.get.v1",
        "task_run.cancel.v1",
    ] {
        assert!(REQUIRED_RUNTIME_CAPABILITIES.contains(&capability));
    }
    for forbidden in [
        "task_run.queue.v1",
        "task_run.admit.v1",
        "task_run.start.v1",
        "task_run.complete.v1",
    ] {
        assert!(!REQUIRED_RUNTIME_CAPABILITIES.contains(&forbidden));
    }
}

/// Compile-time pin for the intended public client calls. Runtime-owned
/// queue/admit/start/complete methods have no public method names to invoke.
#[allow(dead_code, reason = "signature pin")]
async fn public_surface_signature_pin(client: &runne_runtime_client::AuthenticatedRuntimeClient) {
    let _ = client.get_task_run(id(TASK_RUN_ID)).await;
    let _ = client.list_task_runs().await;
    let _ = client
        .cancel_task_run(CancelTaskRunRequest::new(
            identity(CANCEL_COMMAND_ID, "surface-pin"),
            id(TASK_RUN_ID),
            2,
        ))
        .await;
    let _ = client
        .submit_task_run(
            SubmitTaskRunRequest::new(
                identity(COMMAND_ID, "surface-pin"),
                id(CONVERSATION_ID),
                id(WORKSPACE_ID),
                "prompt",
            )
            .expect("valid prompt"),
        )
        .await;
}
