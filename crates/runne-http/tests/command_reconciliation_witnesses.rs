use std::sync::{Arc, Mutex};

use axum::body::Body;
use http::{Request, StatusCode};
use runne_api::{
    CommandReconciliationContext, CommandReconciliationDisposition, CommandReconciliationHostError,
    CommandReconciliationHostPort, CommandReconciliationWitness, ReconciliationOperation,
};
use runne_http::{
    admission::AdmissionState,
    command_reconciliation::CommandReconciliationHttpState,
    health::{HealthState, RecoveryState},
    router::create_router_with_command_reconciliation,
};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const COMMAND: &str = "018f2e3a-7000-7000-8000-000000000301";
const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000302";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000303";
const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000304";

type Calls = Arc<Mutex<Vec<(CommandReconciliationContext, CommandReconciliationWitness)>>>;

#[derive(Clone)]
struct Host(Calls);

impl CommandReconciliationHostPort for Host {
    async fn reconcile_command(
        &self,
        context: CommandReconciliationContext,
        witness: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        self.0.lock().unwrap().push((context, witness));
        Ok(CommandReconciliationDisposition::not_committed_retryable())
    }
}

#[tokio::test]
async fn all_nine_witnesses_reach_the_read_only_host_with_middleware_principal() {
    let calls: Calls = Arc::default();
    let app = create_router_with_command_reconciliation(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        CommandReconciliationHttpState::new(Host(calls.clone())),
    );
    let digest = "07".repeat(32);
    let cases = [
        (
            format!(
                r#"{{"operation":"create_project","projectId":"{PROJECT}","displayName":"Name"}}"#
            ),
            ReconciliationOperation::CreateProject,
        ),
        (
            format!(
                r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1}}"#
            ),
            ReconciliationOperation::ArchiveProject,
        ),
        (
            format!(
                r#"{{"operation":"delete_project","projectId":"{PROJECT}","expectedVersion":1}}"#
            ),
            ReconciliationOperation::DeleteProject,
        ),
        (
            format!(
                r#"{{"operation":"rename_project","projectId":"{PROJECT}","expectedVersion":1,"displayName":"Renamed"}}"#
            ),
            ReconciliationOperation::RenameProject,
        ),
        (
            format!(
                r#"{{"operation":"create_workspace","workspaceId":"{WORKSPACE}","projectId":"{PROJECT}","displayName":"Name"}}"#
            ),
            ReconciliationOperation::CreateWorkspace,
        ),
        (
            format!(
                r#"{{"operation":"bind_workspace_root","workspaceId":"{WORKSPACE}","expectedVersion":1,"admissionDigest":"{digest}"}}"#
            ),
            ReconciliationOperation::BindWorkspaceRoot,
        ),
        (
            format!(
                r#"{{"operation":"open_workspace","workspaceId":"{WORKSPACE}","expectedVersion":1}}"#
            ),
            ReconciliationOperation::OpenWorkspace,
        ),
        (
            format!(
                r#"{{"operation":"create_conversation","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}"}}"#
            ),
            ReconciliationOperation::CreateConversation,
        ),
        (
            format!(
                r#"{{"operation":"generate_conversation_text","conversationId":"{CONVERSATION}","expectedVersion":1,"text":"hello"}}"#
            ),
            ReconciliationOperation::GenerateConversationText,
        ),
    ];
    for (body, _) in &cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/commands/reconcile")
                    .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
                    .header("x-command-id", COMMAND)
                    .header("idempotency-key", "reconcile-test")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), cases.len());
    for ((context, witness), (_, operation)) in calls.iter().zip(cases) {
        assert_eq!(context.command_id().to_string(), COMMAND);
        assert_eq!(context.idempotency_key().as_str(), "reconcile-test");
        assert_eq!(context.principal().as_str(), "local-owner");
        assert_eq!(witness.operation(), operation);
    }
}
