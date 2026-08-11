#![cfg(all(unix, feature = "desktop-protected"))]

use std::sync::{Arc, Mutex};

use gocode_api::{
    ApiPrincipalId, BindWorkspaceRootCommand, LaunchSecret, ProjectCommandContext,
    ProjectWorkspaceCommandHostPort, RootHandleTransferAuthenticator, RootHandleTransferContext,
    RootHandleTransferOffer, RuntimeSessionBinding, StableRuntimeBinding,
};
use gocode_application::local_session::LocalSessionService;
use gocode_application::ports::{
    ProjectWorkspaceRepository, RootAdmissionVerifier, RootAdmissionVerifierError,
    RuntimeAuthorityId,
};
use gocode_daemon::application::root_handle_admission::{
    RootAdmissionGateway, RootHandleAdmissionAuthority,
};
use gocode_domain::{
    event::Sensitivity,
    id::{CommandId, DaemonInstanceId, EventLogLineageId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
use gocode_platform_desktop::VerifiedRootHandle;
use gocode_runtime::RuntimeProjectWorkspaceHost;
use gocode_security::SecretBroker;
use gocode_store::{ProjectWorkspaceStore, schema, store::StoreTransaction};

#[test]
fn retained_native_root_issues_only_current_owned_workspace_admission() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("event-log.db");
    let writer = schema::open_with_pragmas(database.to_str().unwrap()).unwrap();
    schema::apply_migrations(&writer).unwrap();
    let reader = rusqlite::Connection::open(&database).unwrap();
    reader.execute_batch("PRAGMA query_only = ON;").unwrap();
    let runtime_authority = "root-admission-test-authority".to_owned();
    let store = StoreTransaction::open_with_connections(
        database.to_str().unwrap(),
        writer,
        reader,
        RuntimeAuthorityId(runtime_authority.clone()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let project = ProjectId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let workspace = WorkspaceId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    repository
        .create_project(
            "local-owner",
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("root-project").unwrap(),
            Project::create(
                project,
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "local-owner",
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("root-workspace").unwrap(),
            Workspace::create(
                workspace,
                project,
                ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    let authority_id = *uuid::Uuid::now_v7().as_bytes();
    let session_id = *uuid::Uuid::now_v7().as_bytes();
    let binding = RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            authority_id,
            ApiPrincipalId::new("local-owner").unwrap(),
            EventLogLineageId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            "fixture",
            [1; 32],
            [2; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
        1,
        session_id,
        0,
        Sensitivity::Public,
        [3; 32],
    )
    .unwrap();
    let sessions = Arc::new(Mutex::new(LocalSessionService::new(binding, [4; 32])));
    let keys = LaunchSecret::from_bytes([5; 32]).unwrap().derive_keys();
    let issuer = RootHandleAdmissionAuthority::new(
        &keys,
        repository.clone(),
        runtime_authority,
        Arc::clone(&sessions),
    );
    let gateway = RootAdmissionGateway::protected(Arc::clone(&issuer));
    let now = unix_millis();
    let context = RootHandleTransferContext::new(
        authority_id,
        session_id,
        1,
        std::process::id(),
        std::process::id(),
        rustix::process::geteuid().as_raw(),
        workspace,
        1,
        *uuid::Uuid::now_v7().as_bytes(),
        now - 1,
        now + 10_000,
    )
    .unwrap();
    let transfer = RootHandleTransferOffer::new(
        context,
        1,
        &RootHandleTransferAuthenticator::from_protected_activation(&keys),
    )
    .unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let admission = issuer.admit(&transfer, root, now).unwrap();
    assert_eq!(
        gateway
            .verify_root_admission(admission)
            .unwrap()
            .workspace_id(),
        workspace
    );
    let token = issuer
        .admit(
            &transfer,
            VerifiedRootHandle::open(directory.path()).unwrap(),
            now,
        )
        .unwrap()
        .encode_token()
        .unwrap();
    let unregistered = RootAdmissionGateway::protected(RootHandleAdmissionAuthority::new(
        &keys,
        repository.clone(),
        "root-admission-test-authority".into(),
        Arc::clone(&sessions),
    ));
    assert!(
        unregistered
            .verify_root_admission(gocode_api::RootHandleAdmission::decode_token(&token).unwrap())
            .is_err()
    );
    let host = RuntimeProjectWorkspaceHost::new(repository, gateway.clone(), gateway.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let command = |key: &str| ProjectCommandContext {
        command_id: CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: gocode_api::ApiActor::new("desktop").unwrap(),
    };
    let first = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: gocode_api::RootHandleAdmission::decode_token(&token).unwrap(),
    };
    assert_eq!(
        runtime
            .block_on(host.bind_workspace_root(command("root-bind-1"), first))
            .unwrap()
            .new_version,
        2
    );
    let replay = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: gocode_api::RootHandleAdmission::decode_token(&token).unwrap(),
    };
    assert!(
        runtime
            .block_on(host.bind_workspace_root(command("root-bind-2"), replay))
            .is_err()
    );
    issuer.fence().unwrap();
    let current = unix_millis();
    let fenced_offer = RootHandleTransferOffer::new(
        RootHandleTransferContext::new(
            authority_id,
            session_id,
            1,
            std::process::id(),
            std::process::id(),
            rustix::process::geteuid().as_raw(),
            workspace,
            2,
            *uuid::Uuid::now_v7().as_bytes(),
            current - 1,
            current + 10_000,
        )
        .unwrap(),
        2,
        &RootHandleTransferAuthenticator::from_protected_activation(&keys),
    )
    .unwrap();
    let fenced = issuer
        .admit(
            &fenced_offer,
            VerifiedRootHandle::open(directory.path()).unwrap(),
            current,
        )
        .unwrap();
    issuer.fence().unwrap();
    assert!(matches!(
        gateway.verify_root_admission(fenced),
        Err(RootAdmissionVerifierError::Rejected)
    ));
    let expired = RootHandleTransferOffer::new(
        RootHandleTransferContext::new(
            authority_id,
            session_id,
            1,
            std::process::id(),
            std::process::id(),
            rustix::process::geteuid().as_raw(),
            workspace,
            2,
            *uuid::Uuid::now_v7().as_bytes(),
            1,
            2,
        )
        .unwrap(),
        3,
        &RootHandleTransferAuthenticator::from_protected_activation(&keys),
    )
    .unwrap();
    let expired = issuer
        .admit(
            &expired,
            VerifiedRootHandle::open(directory.path()).unwrap(),
            1,
        )
        .unwrap();
    assert!(matches!(
        gateway.verify_root_admission(expired),
        Err(RootAdmissionVerifierError::Rejected)
    ));
}

fn unix_millis() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
