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
    let conversation = prepare_conversation(client, "service").await?;
    let generated = client
        .generate_text(generate_request(conversation, "service-generate")?)
        .await
        .map_err(|error| failure(runtime, error.kind()))?;
    if generated.assistant_message.text != "fixture response" {
        return Err("point-of-use-response");
    }
    (count(runtime, "fixture-provider-request-count") == 1)
        .then_some(())
        .ok_or("point-of-use-cardinality")
}

pub(super) async fn prove_service_loss_is_fenced(
    client: &AuthenticatedRuntimeClient,
    runtime: &Path,
) -> Result<(), &'static str> {
    let connections = count(runtime, "fixture-provider-connection-count");
    let requests = count(runtime, "fixture-provider-request-count");
    let conversation = prepare_conversation(client, "service-loss").await?;
    let result = client
        .generate_text(generate_request(conversation, "service-loss-generate")?)
        .await;
    match result {
        Ok(_) => return Err("service-loss-unexpected-success"),
        Err(error)
            if matches!(
                error.kind(),
                RuntimeApiErrorKind::Unavailable | RuntimeApiErrorKind::InvalidResponse
            ) => {}
        Err(error) => return Err(service_loss_error(error.kind())),
    }
    (count(runtime, "fixture-provider-connection-count") == connections
        && count(runtime, "fixture-provider-request-count") == requests)
        .then_some(())
        .ok_or("service-loss-reached-provider")
}

const fn service_loss_error(kind: RuntimeApiErrorKind) -> &'static str {
    match kind {
        RuntimeApiErrorKind::InvalidRequest => "service-loss-invalid-request",
        RuntimeApiErrorKind::Unauthorized => "service-loss-unauthorized",
        RuntimeApiErrorKind::NotFound => "service-loss-not-found",
        RuntimeApiErrorKind::Conflict => "service-loss-conflict",
        RuntimeApiErrorKind::Backpressure => "service-loss-backpressure",
        RuntimeApiErrorKind::ResponseTooLarge => "service-loss-response-size",
        RuntimeApiErrorKind::InvalidResponse => "service-loss-invalid-response",
        RuntimeApiErrorKind::Incompatible => "service-loss-incompatible",
        RuntimeApiErrorKind::Unavailable => "service-loss-unavailable",
    }
}

async fn prepare_conversation(
    client: &AuthenticatedRuntimeClient,
    label: &str,
) -> Result<CanonicalId, &'static str> {
    let project = CanonicalId::now_v7();
    let workspace = CanonicalId::now_v7();
    let conversation = CanonicalId::now_v7();
    client
        .create_project(
            CreateProjectRequest::new(
                command(&format!("{label}-project"))?,
                project,
                "Service project",
            )
            .map_err(|_| "point-of-use-project-request")?,
        )
        .await
        .map_err(|_| "point-of-use-project")?;
    client
        .create_workspace(
            CreateWorkspaceRequest::new(
                command(&format!("{label}-workspace"))?,
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
            command(&format!("{label}-conversation"))?,
            conversation,
            workspace,
        ))
        .await
        .map_err(|_| "point-of-use-conversation")?;
    Ok(conversation)
}

fn generate_request(
    conversation: CanonicalId,
    label: &str,
) -> Result<GenerateTextRequest, &'static str> {
    GenerateTextRequest::new(command(label)?, conversation, 1, "fixture input")
        .map_err(|_| "point-of-use-generate-request")
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
