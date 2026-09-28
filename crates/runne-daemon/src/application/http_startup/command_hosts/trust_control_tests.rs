use super::*;

use runne_application::ports::{ProjectWorkspaceRepository, RuntimeAuthorityId};
use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustStatus, TrustToken};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;

const PROJECT_BYTES: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 5];
const WORKSPACE_BYTES: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];

struct Fixture {
    _directory: tempfile::TempDir,
    project: ProjectId,
    workspace: WorkspaceId,
    repository: ProjectWorkspaceStore,
    persistence: Arc<runne_store::ProjectTrustStore>,
    host: TrustControlHost,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("directory");
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).expect("daemon directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("private fixture directory");
    }
    let path = daemon.join("control.sqlite");
    let store = StoreTransaction::open(
        path.to_str().expect("path"),
        RuntimeAuthorityId("project-trust-control-test".into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .expect("canonical store");
    let repository = ProjectWorkspaceStore::from_store(store);
    let project = ProjectId::from_bytes(PROJECT_BYTES);
    let workspace = WorkspaceId::from_bytes(WORKSPACE_BYTES);
    repository
        .create_project(
            PRINCIPAL,
            CommandId::from_bytes([1; 16]),
            &IdempotencyKey::new("project").expect("key"),
            Project::create(
                project,
                ProjectWorkspaceDisplayName::new("Safe project name".into()).expect("name"),
            ),
        )
        .expect("create project");
    repository
        .create_workspace(
            PRINCIPAL,
            CommandId::from_bytes([2; 16]),
            &IdempotencyKey::new("workspace").expect("key"),
            Workspace::create(
                workspace,
                project,
                ProjectWorkspaceDisplayName::new("Safe workspace name".into()).expect("name"),
            ),
        )
        .expect("create workspace");
    let persistence = Arc::new(
        runne_store::ProjectTrustStore::open(
            &path,
            [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        )
        .expect("trust store"),
    );
    let trust = Arc::new(ProjectTrustPolicyAuthority::new(persistence.clone()));
    let host = TrustControlHost::new(
        repository.clone(),
        trust,
        RootAdmissionGateway::unavailable(),
    );
    Fixture {
        _directory: directory,
        project,
        workspace,
        repository,
        persistence,
        host,
    }
}

fn request(
    snapshot: &Snapshot,
    decision: Decision,
    root: Option<u64>,
) -> ProjectTrustControlRequest {
    ProjectTrustControlRequest {
        decision,
        expected_epoch: snapshot.epoch,
        expected_revision: snapshot.revision,
        expected_project_version: snapshot.project_version,
        expected_workspace_version: snapshot.workspace_version,
        expected_root_admission_version: root,
    }
}

#[tokio::test]
async fn owned_snapshot_without_root_allows_revoke_but_not_confirm_and_replay_conflicts() {
    let fixture = fixture();
    fixture
        .repository
        .open_workspace(
            PRINCIPAL,
            CommandId::from_bytes([3; 16]),
            &IdempotencyKey::new("open").expect("key"),
            fixture.workspace,
            1,
        )
        .expect("open workspace");
    let principal = ApiPrincipalId::new(PRINCIPAL).expect("principal");
    let snapshot = fixture
        .host
        .get_project_trust(principal.clone(), fixture.project, fixture.workspace)
        .await
        .expect("safe owned snapshot while root is disconnected");
    assert_eq!(snapshot.root_admission_version, None);
    assert_eq!(snapshot.status, Status::Untrusted);
    assert_eq!(snapshot.provenance, Provenance::Default);
    assert_eq!(snapshot.project_name, "Safe project name");

    assert_eq!(
        fixture
            .host
            .decide_project_trust(
                principal.clone(),
                fixture.project,
                fixture.workspace,
                request(&snapshot, Decision::ConfirmProject, None),
            )
            .await,
        Err(Error::RootUnavailable)
    );
    let revoked = fixture
        .host
        .decide_project_trust(
            principal.clone(),
            fixture.project,
            fixture.workspace,
            request(&snapshot, Decision::RevokeProject, None),
        )
        .await
        .expect("revoke without root");
    assert_eq!(revoked.revision, snapshot.revision + 1);
    assert_eq!(revoked.status, Status::Untrusted);
    assert_eq!(revoked.provenance, Provenance::User);
    assert_eq!(
        fixture
            .host
            .decide_project_trust(
                principal,
                fixture.project,
                fixture.workspace,
                request(&snapshot, Decision::RevokeProject, None),
            )
            .await,
        Err(Error::Conflict)
    );
}

#[tokio::test]
async fn closed_archived_foreign_and_managed_projects_are_not_disclosed_or_overridden() {
    let fixture = fixture();
    let owner = ApiPrincipalId::new(PRINCIPAL).expect("principal");
    let stranger = ApiPrincipalId::new("other-local-principal").expect("principal");
    assert_eq!(
        fixture
            .host
            .get_project_trust(owner.clone(), fixture.project, fixture.workspace)
            .await,
        Err(Error::NotFound)
    );
    assert_eq!(
        fixture
            .host
            .get_project_trust(stranger, fixture.project, fixture.workspace)
            .await,
        Err(Error::NotFound)
    );

    fixture
        .repository
        .open_workspace(
            PRINCIPAL,
            CommandId::from_bytes([4; 16]),
            &IdempotencyKey::new("open").expect("key"),
            fixture.workspace,
            1,
        )
        .expect("open workspace");
    let snapshot = fixture
        .host
        .get_project_trust(owner.clone(), fixture.project, fixture.workspace)
        .await
        .expect("owned snapshot");
    let project_key = ProjectTrustProjectId::from_bytes(*fixture.project.as_bytes());
    fixture
        .persistence
        .commit(
            project_key,
            ProjectTrustStatus::Untrusted,
            1,
            TrustToken::new(snapshot.epoch, snapshot.revision),
        )
        .expect("synthetic managed deny");
    let managed = fixture
        .host
        .get_project_trust(owner.clone(), fixture.project, fixture.workspace)
        .await
        .expect("managed snapshot");
    assert_eq!(managed.provenance, Provenance::Managed);
    assert_eq!(managed.managed_deny_mask, 1);
    assert_eq!(
        fixture
            .host
            .decide_project_trust(
                owner.clone(),
                fixture.project,
                fixture.workspace,
                request(&managed, Decision::RevokeProject, None),
            )
            .await,
        Err(Error::ManagedPolicy)
    );

    fixture
        .repository
        .archive_project(
            PRINCIPAL,
            CommandId::from_bytes([5; 16]),
            &IdempotencyKey::new("archive").expect("key"),
            fixture.project,
            managed.project_version,
        )
        .expect("archive project");
    assert_eq!(
        fixture
            .host
            .get_project_trust(owner, fixture.project, fixture.workspace)
            .await,
        Err(Error::NotFound)
    );
}
