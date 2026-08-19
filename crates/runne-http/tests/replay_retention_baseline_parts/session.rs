use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_api::{ApiActor, ApiCommandContext, CreateConversationInput};
use runne_application::local_session::{
    BootstrapProof, LocalSessionService, bootstrap_proof_transcript,
};
use runne_application::ports::{
    ApplicationCommandContext, PrincipalId, ProjectWorkspaceRepository,
};
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, IdempotencyKey, ProjectId};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};
use hmac::{Hmac, Mac};

pub(super) fn binding() -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            AUTHORITY,
            ApiPrincipalId::new("local-owner").unwrap(),
            EventLogLineageId::from_bytes(LINEAGE),
            "runne-ui-client/2",
            [0x48; 32],
            [0x49; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(uuid_v7(0x4a)),
        1,
        uuid_v7(0x4b),
        0,
        Sensitivity::Sensitive,
        [0x4c; 32],
    )
    .unwrap()
}

fn session_layer(binding: RuntimeSessionBinding) -> SessionAuthLayer {
    let mut service = LocalSessionService::new(binding.clone(), SESSION_TOKEN);
    let challenge = service
        .issue_challenge([0x4d; 32], [0x4e; 32], Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&SESSION_TOKEN).unwrap();
    mac.update(&bootstrap_proof_transcript(
        &binding, [0x4e; 32], [0x4d; 32],
    ));
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            SESSION_AUTHORITY,
            Duration::ZERO,
        )
        .unwrap();
    SessionAuthLayer::new(
        Arc::new(Mutex::new(service)),
        binding,
        Arc::new(|| Duration::ZERO),
    )
}

pub(super) fn open_request(
    taskrun_id: TaskRunId,
    authority: Option<[u8; 32]>,
    from_cursor: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/replay/open-session")
        .header("content-type", "application/json");
    if let Some(authority) = authority {
        request = request.header(
            "authorization",
            session_authorization_header(&URL_SAFE_NO_PAD.encode(authority)).unwrap(),
        );
    }
    let body = serde_json::json!({
        "aggregateType": "taskRun",
        "aggregateId": taskrun_id.to_string(),
        "fromCursor": from_cursor,
    });
    request.body(Body::from(body.to_string())).unwrap()
}

pub(super) fn resume_request(baseline: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/replay/resume-from-baseline")
        .header("content-type", "application/json")
        .header(
            "authorization",
            session_authorization_header(&URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY)).unwrap(),
        )
        .body(Body::from(serde_json::json!({"baseline": baseline}).to_string()))
        .unwrap()
}

pub(super) fn api_context() -> ApiCommandContext {
    ApiCommandContext {
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("retention-http-test").unwrap(),
        response_seed: runne_api::ResponseSeed {
            project_id: "test".into(),
            directory: "/test".into(),
            path: None,
            version: "test".into(),
            workspace_id: None,
        },
    }
}

pub(super) fn context(number: u8) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command(number),
        idempotency_key: key(number),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("retention-http-test").unwrap(),
    }
}

pub(super) fn command(number: u8) -> CommandId {
    CommandId::from_bytes(uuid_v7(number))
}
pub(super) fn key(number: u8) -> IdempotencyKey {
    IdempotencyKey::new(format!("retention-http-{number}")).unwrap()
}

pub(super) fn seed_workspace(store: &StoreTransaction, workspace_id: WorkspaceId) {
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = ProjectId::from_bytes(uuid_v7(0x53));
    repository
        .create_project(
            "local-owner",
            command(3),
            &key(3),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Retention test project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "local-owner",
            command(4),
            &key(4),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Retention test workspace".into()).unwrap(),
            ),
        )
        .unwrap();
}

pub(super) const fn uuid_v7(tail: u8) -> [u8; 16] {
    [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, tail,
    ]
}
