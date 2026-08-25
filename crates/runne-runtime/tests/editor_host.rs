use runne_api::{
    ApiActor, ApiPrincipalId, EditorLaunchReceipt, EditorLaunchTargetV1, OpenEditorRequest,
    ProcessCommandContext, WorkspaceEditorHostError, WorkspaceEditorHostPort,
};
use runne_application::ports::WorkspaceEditorProvider;
use runne_domain::id::{CommandId, IdempotencyKey, WorkspaceId};
use runne_runtime::RuntimeWorkspaceEditorHost;

#[derive(Clone)]
struct RecordingProvider;

impl WorkspaceEditorProvider for RecordingProvider {
    fn open_editor(
        &self,
        principal: &str,
        request: &OpenEditorRequest,
    ) -> Result<EditorLaunchReceipt, WorkspaceEditorHostError> {
        assert_eq!(principal, "local-owner");
        assert_eq!(request.relative_path(), "src/main.rs");
        Ok(EditorLaunchReceipt::accepted(request))
    }
}

fn context() -> ProcessCommandContext {
    let id = "018f2e3a-7000-7000-8000-000000000402"
        .parse::<CommandId>()
        .unwrap();
    ProcessCommandContext {
        command_id: id,
        idempotency_key: IdempotencyKey::new("editor-test").unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("desktop").unwrap(),
    }
}

#[tokio::test]
async fn editor_host_delegates_only_the_runtime_owned_request() {
    let host = RuntimeWorkspaceEditorHost::new(RecordingProvider);
    let workspace = "018f2e3a-7000-7000-8000-000000000403"
        .parse::<WorkspaceId>()
        .unwrap();
    let request = OpenEditorRequest::new(
        workspace,
        "src/main.rs",
        EditorLaunchTargetV1::SystemDefault,
    )
    .unwrap();

    let receipt = host.open_editor(context(), request).await.unwrap();
    assert_eq!(receipt.workspace_id(), workspace);
    assert_eq!(receipt.target(), EditorLaunchTargetV1::SystemDefault);
}
