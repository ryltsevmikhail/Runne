use axum::body::{Body, to_bytes};
use gocode_api::{
    AuthoritativeCommandOutcome, CommandReconciliationContext, CommandReconciliationDisposition,
    CommandReconciliationHostError, CommandReconciliationHostPort, CommandReconciliationWitness,
    CommandReconciliationWitnessRef, ConversationCreatedAck, NonNegativeUnixMillis,
    ProjectCommandAck, WorkspaceCommandAck,
};
use gocode_http::{
    admission::AdmissionState,
    command_reconciliation::CommandReconciliationHttpState,
    health::{HealthState, RecoveryState},
    router::create_router_with_command_reconciliation,
};
use http::{Request, StatusCode};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000302";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000303";
const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000304";

#[derive(Clone)]
struct OutcomeHost;

impl CommandReconciliationHostPort for OutcomeHost {
    async fn reconcile_command(
        &self,
        _: CommandReconciliationContext,
        witness: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        let outcome = match witness.view() {
            CommandReconciliationWitnessRef::CreateProject { project_id, .. } => {
                AuthoritativeCommandOutcome::project_created(ProjectCommandAck {
                    project_id,
                    new_version: 1,
                })
            }
            CommandReconciliationWitnessRef::ArchiveProject { project_id, .. } => {
                AuthoritativeCommandOutcome::project_archived(ProjectCommandAck {
                    project_id,
                    new_version: 2,
                })
            }
            CommandReconciliationWitnessRef::DeleteProject { project_id, .. } => {
                AuthoritativeCommandOutcome::project_deleted(ProjectCommandAck {
                    project_id,
                    new_version: 2,
                })
            }
            CommandReconciliationWitnessRef::CreateWorkspace { workspace_id, .. } => {
                AuthoritativeCommandOutcome::workspace_created(WorkspaceCommandAck {
                    workspace_id,
                    new_version: 1,
                })
            }
            CommandReconciliationWitnessRef::BindWorkspaceRoot { workspace_id, .. } => {
                AuthoritativeCommandOutcome::workspace_root_bound(WorkspaceCommandAck {
                    workspace_id,
                    new_version: 2,
                })
            }
            CommandReconciliationWitnessRef::OpenWorkspace { workspace_id, .. } => {
                AuthoritativeCommandOutcome::workspace_opened(WorkspaceCommandAck {
                    workspace_id,
                    new_version: 2,
                })
            }
            CommandReconciliationWitnessRef::CreateConversation {
                conversation_id,
                workspace_id,
            } => AuthoritativeCommandOutcome::conversation_created(ConversationCreatedAck {
                conversation_id,
                workspace_id,
                stream_version: 1,
                committed_at: NonNegativeUnixMillis::new(7).unwrap(),
            }),
            CommandReconciliationWitnessRef::GenerateConversationText { .. } => unreachable!(),
        };
        CommandReconciliationDisposition::durably_recorded(&witness, outcome)
    }
}

#[tokio::test]
async fn seven_non_text_operations_have_exact_closed_response_bodies() {
    let digest = "07".repeat(32);
    let cases = [
        (
            format!(
                r#"{{"operation":"create_project","projectId":"{PROJECT}","displayName":"Name"}}"#
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{PROJECT}","newVersion":1}}}}"#
            ),
        ),
        (
            format!(
                r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1}}"#
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"archive_project","projectId":"{PROJECT}","newVersion":2}}}}"#
            ),
        ),
        (
            format!(
                r#"{{"operation":"delete_project","projectId":"{PROJECT}","expectedVersion":1}}"#
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"delete_project","projectId":"{PROJECT}","newVersion":2}}}}"#
            ),
        ),
        (
            format!(
                r#"{{"operation":"create_workspace","workspaceId":"{WORKSPACE}","projectId":"{PROJECT}","displayName":"Name"}}"#
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_workspace","workspaceId":"{WORKSPACE}","newVersion":1}}}}"#
            ),
        ),
        (
            format!(
                r#"{{"operation":"bind_workspace_root","workspaceId":"{WORKSPACE}","expectedVersion":1,"admissionDigest":"{digest}"}}"#
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"bind_workspace_root","workspaceId":"{WORKSPACE}","newVersion":2}}}}"#
            ),
        ),
        (
            format!(
                r#"{{"operation":"open_workspace","workspaceId":"{WORKSPACE}","expectedVersion":1}}"#
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"open_workspace","workspaceId":"{WORKSPACE}","newVersion":2}}}}"#
            ),
        ),
        (
            format!(
                r#"{{"operation":"create_conversation","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}"}}"#
            ),
            format!(
                r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_conversation","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","streamVersion":1,"committedAt":7}}}}"#
            ),
        ),
    ];
    for (body, expected) in cases {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/commands/reconcile")
            .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
            .header("x-command-id", "018f2e3a-7000-7000-8000-000000000301")
            .header("idempotency-key", "reconcile-test")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap(),
            expected
        );
    }
}

fn app() -> axum::Router {
    create_router_with_command_reconciliation(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        CommandReconciliationHttpState::new(OutcomeHost),
    )
}
