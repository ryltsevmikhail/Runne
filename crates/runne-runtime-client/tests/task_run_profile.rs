#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{
    CanonicalId, REQUIRED_RUNTIME_CAPABILITIES, RuntimeTransportKind, TaskRunState,
    mock_authenticated_runtime_client, protected_profile_matches,
};

const UNUSED_ORIGIN: &str = "http://127.0.0.1:45123";

#[tokio::test]
async fn task_run_read_session_info_exposes_profile_and_capabilities() {
    let client =
        mock_authenticated_runtime_client(UNUSED_ORIGIN, support::session()).expect("client");
    let session = client.session_info();
    assert_eq!(session.profile_id, "gocode-ui-client/2");
    assert_eq!(session.schema_hash, "test");
    assert!(
        session
            .capabilities
            .iter()
            .map(String::as_str)
            .eq(REQUIRED_RUNTIME_CAPABILITIES.iter().copied()),
        "session capabilities must equal the required profile in order"
    );
    assert_eq!(client.transport_kind(), RuntimeTransportKind::ExternalLocal);
    assert!(client.provider_statuses().is_empty());
}

#[tokio::test]
async fn task_run_read_required_capabilities_include_task_run_read_family() {
    for capability in [
        "task_run.submit.v1",
        "task_run.get.v1",
        "task_run.cancel.v1",
    ] {
        assert!(
            REQUIRED_RUNTIME_CAPABILITIES.contains(&capability),
            "{capability} must stay in the required profile"
        );
    }
}

#[tokio::test]
async fn task_run_read_protected_profile_matches_rejects_external_session() {
    let client =
        mock_authenticated_runtime_client(UNUSED_ORIGIN, support::session()).expect("client");
    assert!(
        !protected_profile_matches(&client),
        "an ExternalLocal session must never satisfy the protected profile predicate"
    );
}

#[tokio::test]
async fn task_run_read_external_client_has_no_per_method_capability_gate() {
    let capabilities = vec!["workspace.files.read.v1".to_owned()];
    let body = support::snapshot_json(
        support::TASK_RUN_ID,
        "running",
        2,
        Some(support::ATTEMPT_ID),
        None,
    );
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let (result, requests) = support::drive(
        support::session_with_capabilities(capabilities),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let snapshot = result.expect("read methods must not be capability-gated client-side");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].start_line,
        format!("GET /v1/task-runs/{} HTTP/1.1", support::TASK_RUN_ID)
    );
    assert_eq!(snapshot.state(), TaskRunState::Running);
    assert_eq!(snapshot.stream_version(), 2);
}
