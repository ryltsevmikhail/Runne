use runne_runtime_client::{
    CanonicalId, CommandIdentity, CommandReconciliationOutcome, CommandReconciliationRequest,
    PROTECTED_RUNTIME_CAPABILITIES, RuntimeSessionInfo, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000302";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000303";
const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000304";
const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000305";

#[tokio::test]
async fn task_run_cancellation_outcome_parses_and_correlates() {
    let request = CommandReconciliationRequest::cancel_task_run(identity(), id(TASK_RUN), 3);
    let body = format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"cancel_task_run","taskRunId":"{TASK_RUN}","newVersion":4}}}}"#
    );
    let expected_request = format!(
        r#"{{"operation":"cancel_task_run","taskRunId":"{TASK_RUN}","expectedVersion":3}}"#
    );
    let (origin, server) = serve(body, expected_request).await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();

    let result = client.reconcile_command(request).await.unwrap();
    assert!(matches!(
        result,
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(outcome)
            if matches!(outcome, CommandReconciliationOutcome::TaskRunCancellationRequested(_))
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn eight_non_text_outcomes_parse_and_correlate_to_the_request() {
    let digest = "07".repeat(32);
    let requests = vec![
        CommandReconciliationRequest::create_project(identity(), id(PROJECT), "Name").unwrap(),
        CommandReconciliationRequest::archive_project(identity(), id(PROJECT), 1).unwrap(),
        CommandReconciliationRequest::delete_project(identity(), id(PROJECT), 1).unwrap(),
        CommandReconciliationRequest::rename_project(identity(), id(PROJECT), 1, "Renamed")
            .unwrap(),
        CommandReconciliationRequest::create_workspace(
            identity(),
            id(WORKSPACE),
            id(PROJECT),
            "Name",
        )
        .unwrap(),
        CommandReconciliationRequest::bind_workspace_root(identity(), id(WORKSPACE), 1, digest)
            .unwrap(),
        CommandReconciliationRequest::open_workspace(identity(), id(WORKSPACE), 1).unwrap(),
        CommandReconciliationRequest::create_conversation(
            identity(),
            id(CONVERSATION),
            id(WORKSPACE),
        ),
    ];
    let bodies = vec![
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{PROJECT}","newVersion":1}}}}"#
        ),
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"archive_project","projectId":"{PROJECT}","newVersion":2}}}}"#
        ),
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"delete_project","projectId":"{PROJECT}","newVersion":2}}}}"#
        ),
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"rename_project","projectId":"{PROJECT}","newVersion":2}}}}"#
        ),
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_workspace","workspaceId":"{WORKSPACE}","newVersion":1}}}}"#
        ),
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"bind_workspace_root","workspaceId":"{WORKSPACE}","newVersion":2}}}}"#
        ),
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"open_workspace","workspaceId":"{WORKSPACE}","newVersion":2}}}}"#
        ),
        format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_conversation","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","streamVersion":1,"committedAt":7}}}}"#
        ),
    ];
    let request_bodies = vec![
        format!(r#"{{"operation":"create_project","projectId":"{PROJECT}","displayName":"Name"}}"#),
        format!(r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1}}"#),
        format!(r#"{{"operation":"delete_project","projectId":"{PROJECT}","expectedVersion":1}}"#),
        format!(
            r#"{{"operation":"rename_project","projectId":"{PROJECT}","expectedVersion":1,"displayName":"Renamed"}}"#
        ),
        format!(
            r#"{{"operation":"create_workspace","workspaceId":"{WORKSPACE}","projectId":"{PROJECT}","displayName":"Name"}}"#
        ),
        format!(
            r#"{{"operation":"bind_workspace_root","workspaceId":"{WORKSPACE}","expectedVersion":1,"admissionDigest":"{}"}}"#,
            "07".repeat(32)
        ),
        format!(
            r#"{{"operation":"open_workspace","workspaceId":"{WORKSPACE}","expectedVersion":1}}"#
        ),
        format!(
            r#"{{"operation":"create_conversation","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}"}}"#
        ),
    ];
    for (case, ((request, body), request_body)) in requests
        .into_iter()
        .zip(bodies)
        .zip(request_bodies)
        .enumerate()
    {
        let (origin, server) = serve(body, request_body).await;
        let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
        let result = client.reconcile_command(request).await.unwrap();
        let runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(outcome) =
            result
        else {
            panic!("expected durable outcome")
        };
        assert!(
            matches!(
                (case, outcome),
                (0, CommandReconciliationOutcome::ProjectCreated(_))
                    | (1, CommandReconciliationOutcome::ProjectArchived(_))
                    | (2, CommandReconciliationOutcome::ProjectDeleted(_))
                    | (3, CommandReconciliationOutcome::ProjectRenamed(_))
                    | (4, CommandReconciliationOutcome::WorkspaceCreated(_))
                    | (5, CommandReconciliationOutcome::WorkspaceRootBound(_))
                    | (6, CommandReconciliationOutcome::WorkspaceOpened(_))
                    | (7, CommandReconciliationOutcome::ConversationCreated(_))
            ),
            "case {case}"
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn non_text_operation_id_and_version_mismatches_are_invalid_responses() {
    let wrong = "018f2e3a-7000-7000-8000-000000000399";
    let cases = vec![
        (
            CommandReconciliationRequest::create_project(identity(), id(PROJECT), "Name").unwrap(),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{wrong}","newVersion":1}}}}"#
            ),
        ),
        (
            CommandReconciliationRequest::archive_project(identity(), id(PROJECT), 1).unwrap(),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"archive_project","projectId":"{PROJECT}","newVersion":3}}}}"#
            ),
        ),
        (
            CommandReconciliationRequest::delete_project(identity(), id(PROJECT), 1).unwrap(),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"archive_project","projectId":"{PROJECT}","newVersion":2}}}}"#
            ),
        ),
        (
            CommandReconciliationRequest::rename_project(identity(), id(PROJECT), 1, "Renamed")
                .unwrap(),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"rename_project","projectId":"{PROJECT}","newVersion":3}}}}"#
            ),
        ),
        (
            CommandReconciliationRequest::create_workspace(
                identity(),
                id(WORKSPACE),
                id(PROJECT),
                "Name",
            )
            .unwrap(),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_workspace","workspaceId":"{wrong}","newVersion":1}}}}"#
            ),
        ),
        (
            CommandReconciliationRequest::bind_workspace_root(
                identity(),
                id(WORKSPACE),
                1,
                "07".repeat(32),
            )
            .unwrap(),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"bind_workspace_root","workspaceId":"{WORKSPACE}","newVersion":3}}}}"#
            ),
        ),
        (
            CommandReconciliationRequest::open_workspace(identity(), id(WORKSPACE), 1).unwrap(),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"open_workspace","workspaceId":"{wrong}","newVersion":2}}}}"#
            ),
        ),
        (
            CommandReconciliationRequest::create_conversation(
                identity(),
                id(CONVERSATION),
                id(WORKSPACE),
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_conversation","conversationId":"{CONVERSATION}","workspaceId":"{wrong}","streamVersion":1,"committedAt":7}}}}"#
            ),
        ),
    ];
    for (request, body) in cases {
        let (origin, server) = serve(body, String::new()).await;
        let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
        assert_eq!(
            client.reconcile_command(request).await.unwrap_err().kind(),
            runne_runtime_client::RuntimeApiErrorKind::InvalidResponse
        );
        server.await.unwrap();
    }
}

async fn serve(
    body: String,
    expected_request_body: String,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.contains(&expected_request_body), "{request}");
        stream.write_all(format!("HTTP/1.1 200 OK\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    (origin, server)
}

fn id(value: &str) -> CanonicalId {
    CanonicalId::parse(value).unwrap()
}
fn identity() -> CommandIdentity {
    CommandIdentity::new(id("018f2e3a-7000-7000-8000-000000000301"), "reconcile-test").unwrap()
}
fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities: PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|v| (*v).into())
            .collect(),
        authority_id: "authority".into(),
        principal_id: "principal".into(),
        event_log_lineage_id: "lineage".into(),
        daemon_instance_id: "daemon".into(),
        launch_generation: 1,
        session_id: "session".into(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".into(),
        certificate_sha256: "certificate".into(),
        capability_digest: "digest".into(),
    }
}
