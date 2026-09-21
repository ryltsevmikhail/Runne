//! Shared composition for the NM-06 delivery-gate regression suites: real
//! daemon-side fixture (trust sidecar + canonical conversation store +
//! workspace store) plus direct-SQL mutation helpers, split out of
//! `nm06_delivery_gate.rs` for the source file length budget.

use std::sync::Arc;

use crate::application::trust_delivery::DeliveryTrustGate;
use runne_api::CreateConversationInput;
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{PrincipalId, ProjectWorkspaceRepository, RuntimeAuthorityId};
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
};
use runne_domain::conversation::ConversationContextScope;
use runne_domain::id::{ConversationId, IdempotencyKey};
use runne_security::SecretBroker;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::{ProjectTrustStore, ProjectWorkspaceStore, store::StoreTransaction};

pub(super) const AUTHORITY: &str = "nm06-gate";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000000e2";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-0000000000e3";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-0000000000e1";
pub(super) const TRUST_AUTHORITY: [u8; 16] =
    [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x2a];

pub(super) struct Composed {
    pub(super) directory: tempfile::TempDir,
    pub(super) db_path: std::path::PathBuf,
    pub(super) gate: DeliveryTrustGate,
    pub(super) sidecar: Arc<ProjectTrustStore>,
    pub(super) store: StoreTransaction,
    pub(super) conversation_id: ConversationId,
}

pub(super) fn composition_with(scope: ConversationContextScope, seed_governance: bool) -> Composed {
    let directory = tempfile::tempdir().unwrap();
    let daemon_dir = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let db_path = daemon_dir.join("nm06-gate.sqlite");
    let store = StoreTransaction::open(
        db_path.to_str().unwrap(),
        RuntimeAuthorityId(AUTHORITY.into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    if seed_governance {
        let projects = ProjectWorkspaceStore::from_store(store.clone());
        let project_id = PROJECT_ID.parse().unwrap();
        projects
            .create_project(
                "local-owner",
                runne_domain::id::CommandId::from_bytes([1; 16]),
                &runne_domain::id::IdempotencyKey::new("nm06-g-p").unwrap(),
                runne_domain::project_workspace::Project::create(
                    project_id,
                    runne_domain::project_workspace::ProjectWorkspaceDisplayName::new("p".into())
                        .unwrap(),
                ),
            )
            .unwrap();
        projects
            .create_workspace(
                "local-owner",
                runne_domain::id::CommandId::from_bytes([2; 16]),
                &runne_domain::id::IdempotencyKey::new("nm06-g-w").unwrap(),
                runne_domain::project_workspace::Workspace::create(
                    WORKSPACE_ID.parse().unwrap(),
                    project_id,
                    runne_domain::project_workspace::ProjectWorkspaceDisplayName::new("w".into())
                        .unwrap(),
                ),
            )
            .unwrap();
    }
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    ConversationService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
    )
    .create_from_application(
        &{
            use runne_application::ports::ApplicationCommandContext;
            ApplicationCommandContext {
                command_id: "018f2e3a-7000-7000-8000-0000000000e4".parse().unwrap(),
                idempotency_key: IdempotencyKey::new("nm06-g-create").unwrap(),
                principal_id: PrincipalId("local-owner".into()),
                actor: runne_domain::event::Actor::new("nm06-gate").unwrap(),
            }
        },
        CreateConversationInput {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            command_id: "018f2e3a-7000-7000-8000-0000000000e4".parse().unwrap(),
            idempotency_key: IdempotencyKey::new("nm06-g-create").unwrap(),
            scope,
        },
    )
    .unwrap();
    let sidecar = Arc::new(ProjectTrustStore::open(&db_path, TRUST_AUTHORITY).unwrap());
    let persistence: Arc<dyn ProjectTrustPersistence> = sidecar.clone();
    let authority = Arc::new(ProjectTrustPolicyAuthority::new(persistence));
    let gate = DeliveryTrustGate::open(Arc::clone(&authority), &store);
    Composed {
        directory,
        db_path,
        gate,
        sidecar,
        store,
        conversation_id,
    }
}

pub(super) fn project() -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes(
        *PROJECT_ID
            .parse::<runne_domain::id::ProjectId>()
            .unwrap()
            .as_bytes(),
    )
}

pub(super) fn set_status(sidecar: &ProjectTrustStore, status: ProjectTrustStatus) {
    // CAS against the current durable token (rev0 default when absent).
    let record = sidecar.load(project()).unwrap();
    sidecar
        .commit(project(), status, 0, record.token())
        .unwrap();
}

pub(super) fn delete_trust_rows(db_path: &std::path::Path) {
    let mut sidecar_path = db_path.to_path_buf().into_os_string();
    sidecar_path.push(".project-trust");
    let conn = rusqlite::Connection::open(&sidecar_path).unwrap();
    conn.execute("DELETE FROM project_trust", []).unwrap();
}

pub(super) fn delete_workspace(db_path: &std::path::Path) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute(
        "DELETE FROM workspaces WHERE workspace_id = ?1",
        rusqlite::params![
            WORKSPACE_ID
                .parse::<runne_domain::id::WorkspaceId>()
                .unwrap()
                .as_bytes()
        ],
    )
    .unwrap();
}

/// Reopens store, trust sidecar and gate over the SAME durable state
/// (restart variant of any scenario).
pub(super) fn reopen_gate(db_path: &std::path::Path) -> (StoreTransaction, DeliveryTrustGate) {
    // Mirrors the daemon restart path: validated reopen of the existing
    // database (writer + reader), not a first-open admission.
    let reopened = |mode| {
        runne_store::schema::reopen_managed_connection_validated(db_path, mode, |_| Ok(())).unwrap()
    };
    let writer = reopened(runne_store::schema::ConnectionMode::ValidatedReopen);
    let reader = reopened(runne_store::schema::ConnectionMode::ValidatedReopen);
    let store = StoreTransaction::open_with_connections(
        db_path.to_str().unwrap(),
        writer,
        reader,
        RuntimeAuthorityId(AUTHORITY.into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let sidecar = Arc::new(ProjectTrustStore::open(db_path, TRUST_AUTHORITY).unwrap());
    let persistence: Arc<dyn ProjectTrustPersistence> = sidecar;
    let authority = Arc::new(ProjectTrustPolicyAuthority::new(persistence));
    let gate = DeliveryTrustGate::open(authority, &store);
    (store, gate)
}
