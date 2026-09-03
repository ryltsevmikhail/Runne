use std::fs;
use std::path::Path;

use runne_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, CreateConversationRequest,
    CreateProjectRequest, CreateWorkspaceRequest, GenerateTextRequest, RuntimeApiErrorKind,
};

pub(super) async fn prove(
    client: &AuthenticatedRuntimeClient,
    runtime: &Path,
) -> Result<(), &'static str> {
    let project = CanonicalId::now_v7();
    let workspace = CanonicalId::now_v7();
    let conversation = CanonicalId::now_v7();
    client
        .create_project(
            CreateProjectRequest::new(command("service-project")?, project, "Service project")
                .map_err(|_| "point-of-use-project-request")?,
        )
        .await
        .map_err(|_| "point-of-use-project")?;
    client
        .create_workspace(
            CreateWorkspaceRequest::new(
                command("service-workspace")?,
                project,
                workspace,
                "Service workspace",
            )
            .map_err(|_| "point-of-use-workspace-request")?,
        )
        .await
        .map_err(|_| "point-of-use-workspace")?;
    client
        .create_conversation(CreateConversationRequest::new(
            command("service-conversation")?,
            conversation,
            workspace,
        ))
        .await
        .map_err(|_| "point-of-use-conversation")?;
    let generated = client
        .generate_text(
            GenerateTextRequest::new(
                command("service-generate")?,
                conversation,
                1,
                "fixture input",
            )
            .map_err(|_| "point-of-use-generate-request")?,
        )
        .await
        .map_err(|error| failure(runtime, error.kind()))?;
    if generated.assistant_message.text != "fixture response" {
        return Err("point-of-use-response");
    }
    (count(runtime, "fixture-provider-request-count") == 1)
        .then_some(())
        .ok_or("point-of-use-cardinality")
}

fn failure(runtime: &Path, kind: RuntimeApiErrorKind) -> &'static str {
    let connected = count(runtime, "fixture-provider-connection-count") > 0;
    let accepted = count(runtime, "fixture-provider-request-count") > 0;
    match (accepted, connected, kind) {
        (true, _, _) => "point-of-use-provider-response",
        (false, true, _) => "point-of-use-provider-request-rejected",
        (false, false, RuntimeApiErrorKind::Unavailable) => "point-of-use-before-provider",
        (false, false, _) => "point-of-use-runtime-response",
    }
}

fn count(runtime: &Path, name: &str) -> u64 {
    fs::read_to_string(runtime.join(name))
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

fn command(label: &str) -> Result<CommandIdentity, &'static str> {
    CommandIdentity::new(CanonicalId::now_v7(), format!("slice-e-{label}"))
        .map_err(|_| "point-of-use-command")
}
