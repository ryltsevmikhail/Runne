//! NM-06 delivery-gate regression suite: the exact scenarios required before
//! the delivery trust boundary may be called complete. Real daemon-side
//! composition: trust sidecar + canonical conversation store + workspace
//! store, driven through `DeliveryTrustGate` (the same gate wired into
//! replay authorization and provider dispatch).

use std::sync::Arc;

use crate::application::trust_delivery::DeliveryTrustGate;
use runne_api::CreateConversationInput;
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{PrincipalId, ProjectWorkspaceRepository, RuntimeAuthorityId};
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
};
use runne_domain::id::{ConversationId, IdempotencyKey};
use runne_security::SecretBroker;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::{ProjectTrustStore, ProjectWorkspaceStore, store::StoreTransaction};

const AUTHORITY: &str = "nm06-gate";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000000e2";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-0000000000e3";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-0000000000e1";
const TRUST_AUTHORITY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x2a];

struct Composed {
    directory: tempfile::TempDir,
    db_path: std::path::PathBuf,
    gate: DeliveryTrustGate,
    sidecar: Arc<ProjectTrustStore>,
    store: StoreTransaction,
    conversation_id: ConversationId,
}

fn composition() -> Composed {
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

fn project() -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes(
        *PROJECT_ID
            .parse::<runne_domain::id::ProjectId>()
            .unwrap()
            .as_bytes(),
    )
}

fn set_status(sidecar: &ProjectTrustStore, status: ProjectTrustStatus) {
    // CAS against the current durable token (rev0 default when absent).
    let record = sidecar.load(project()).unwrap();
    sidecar
        .commit(project(), status, 0, record.token())
        .unwrap();
}

#[test]
fn nm06_delivery_gate_revision_revoke_and_storage_semantics() {
    let Composed {
        directory: _directory,
        db_path,
        gate,
        sidecar,
        store,
        conversation_id,
    } = composition();

    // 1. Never-governed project, live-only conversation (no committed
    //    events): confirmed absence => allow.
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("live-only session admits");

    // 2. Explicit UNTRUSTED record: governed and denied.
    set_status(&sidecar, ProjectTrustStatus::Untrusted);
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // 3. Grant => allow. 4. Revoke => deny (revision change between
    //    deliveries is honored in both directions). 5. Re-grant => allow.
    set_status(&sidecar, ProjectTrustStatus::Trusted);
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("trusted project admits");
    set_status(&sidecar, ProjectTrustStatus::Untrusted);
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );
    set_status(&sidecar, ProjectTrustStatus::Trusted);
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("re-grant admits again");

    // 6. Trust-record disappearance (sidecar rows dropped): the stream still
    //    replays as text-only => allow under the explicit text-only
    //    contract; single-user residual documented in the report.
    {
        let mut sidecar_path = db_path.clone().into_os_string();
        sidecar_path.push(".project-trust");
        let conn = rusqlite::Connection::open(&sidecar_path).unwrap();
        conn.execute("DELETE FROM project_trust", []).unwrap();
    }
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("ungoverned text-only stream admits");

    // 7. Workspace disappearance (R-9): the replayed stream is still
    //    text-only => allow (documented boundary).
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
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
    gate.ensure_conversation_trusted("local-owner", conversation_id)
        .expect("unregistered workspace admits under text-only contract");

    // 8. Storage error (durable event corrupted): read failure must BLOCK
    //    delivery instead of being treated as an absent aggregate.
    let corrupted = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("UPDATE events SET payload = X'00' WHERE sequence = 1", [])
            .unwrap()
    };
    assert!(corrupted > 0, "event row must exist for corruption");
    assert!(
        gate.ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // 9. Closed gate (authority lost): fail closed.
    let closed = DeliveryTrustGate::closed();
    assert!(
        closed
            .ensure_conversation_trusted("local-owner", conversation_id)
            .is_err()
    );

    // 10. Confirmed absence (unknown conversation): allow — there is no
    //     captured material; the upstream store answers empty/404.
    let unknown: ConversationId = "018f2e3a-7000-7000-8000-0000000000e9".parse().unwrap();
    gate.ensure_conversation_trusted("local-owner", unknown)
        .expect("confirmed absence admits (nothing to deliver)");
    drop(store);
}
