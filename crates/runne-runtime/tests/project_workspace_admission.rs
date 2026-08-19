use runne_api::{
    ApiActor, ApiPrincipalId, BindWorkspaceRootCommand, CreateProjectCommand,
    CreateWorkspaceCommand, ProjectCommandContext, ProjectQueryContext,
    ProjectWorkspaceCommandHostPort, ProjectWorkspaceDisplayNameInput, ProjectWorkspaceHostError,
    ProjectWorkspaceQueryHostPort, RootAdmissionVerificationContext,
};
use runne_application::ports::{
    CurrentRootAdmissionContext, RootAdmissionLease, RootAdmissionVerifier,
    RootAdmissionVerifierError, RuntimeAuthorityId,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use runne_runtime::RuntimeProjectWorkspaceHost;
use runne_security::SecretBroker;
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};
use std::sync::{Arc, Mutex};

#[path = "project_workspace_admission/barrier.rs"]
mod barrier;
#[path = "project_workspace_admission/invariants.rs"]
mod invariants;
#[path = "project_workspace_admission/mismatch.rs"]
mod mismatch;
#[path = "project_workspace_admission/race.rs"]
mod race;

const PROJECT: &str = "018f47a2-4f8c-7b52-8c35-7a3a14c2d9e1";
const WORKSPACE: &str = "018f47a2-4f8c-7b52-8c35-7a3a14c2d9e2";

fn name(value: &str) -> ProjectWorkspaceDisplayNameInput {
    ProjectWorkspaceDisplayNameInput::new(value.into()).unwrap()
}

#[derive(Clone)]
struct Current(RootAdmissionVerificationContext);
impl CurrentRootAdmissionContext for Current {
    type Lease = Self;
    fn acquire_root_admission_lease(&self) -> Result<Self::Lease, RootAdmissionVerifierError> {
        Ok(self.clone())
    }
}
impl RootAdmissionLease for Current {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        Ok(self.0.clone())
    }
}

struct Verifier(Mutex<Option<runne_api::VerifiedRootAdmissionClaims>>);
impl RootAdmissionVerifier for Verifier {
    fn verify_root_admission(
        &self,
        _: runne_api::RootHandleAdmission,
    ) -> Result<runne_api::VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or(RootAdmissionVerifierError::Rejected)
    }
}

fn command(principal: &str, value: u8) -> ProjectCommandContext {
    ProjectCommandContext {
        command_id: CommandId::from_bytes([value; 16]),
        idempotency_key: IdempotencyKey::new(format!("key-{value}")).unwrap(),
        principal: ApiPrincipalId::new(principal).unwrap(),
        actor: ApiActor::new("desktop").unwrap(),
    }
}

fn admission_context() -> RootAdmissionVerificationContext {
    RootAdmissionVerificationContext::new(
        RootAdmissionVerificationContext::authority_digest_for("admission-test"),
        [2; 16],
        1,
        RootAdmissionVerificationContext::principal_digest_for("owner"),
        3,
        1,
        100,
    )
    .unwrap()
}

fn host(
    store: StoreTransaction,
    current: RootAdmissionVerificationContext,
    claims: runne_api::VerifiedRootAdmissionClaims,
) -> RuntimeProjectWorkspaceHost<ProjectWorkspaceStore, Current, Verifier> {
    RuntimeProjectWorkspaceHost::new(
        ProjectWorkspaceStore::from_store(store),
        Current(current),
        Verifier(Mutex::new(Some(claims))),
    )
}

fn claims(
    context: RootAdmissionVerificationContext,
    workspace: WorkspaceId,
    nonce: u8,
    expiry: u64,
) -> runne_api::VerifiedRootAdmissionClaims {
    runne_api::test_support::claims(context, workspace, 1, [nonce; 16], expiry, [nonce; 32])
}

fn test_database_path(directory: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
    let runtime = directory.path().join("runtime");
    let daemon = runtime.join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    daemon.join(name)
}

fn store() -> (tempfile::TempDir, std::path::PathBuf, StoreTransaction) {
    let directory = tempfile::tempdir().unwrap();
    let guard: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let path = test_database_path(&directory, "admission.sqlite");
    let store = StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId("admission-test".into()),
        guard,
    )
    .unwrap();
    (directory, path, store)
}

async fn create_workspace(store: StoreTransaction, workspace: WorkspaceId) {
    let host = host(
        store,
        admission_context(),
        claims(admission_context(), workspace, 90, 200),
    );
    let project = PROJECT.parse::<ProjectId>().unwrap();
    host.create_project(
        command("owner", 1),
        CreateProjectCommand {
            project_id: project,
            display_name: name("Project"),
        },
    )
    .await
    .unwrap();
    host.create_workspace(
        command("owner", 2),
        CreateWorkspaceCommand {
            workspace_id: workspace,
            project_id: project,
            display_name: name("Workspace"),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn root_admission_is_single_use_but_exact_receipt_retry_replays() {
    let (_directory, _path, store) = store();
    let workspace = WORKSPACE.parse().unwrap();
    create_workspace(store.clone(), workspace).await;
    let first = host(
        store.clone(),
        admission_context(),
        claims(admission_context(), workspace, 3, 200),
    );
    let request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: runne_api::test_support::admission(),
    };
    assert_eq!(
        first
            .bind_workspace_root(command("owner", 3), request)
            .await
            .unwrap()
            .new_version,
        2
    );
    let replay = host(
        store.clone(),
        admission_context(),
        claims(admission_context(), workspace, 3, 200),
    );
    let retry = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: runne_api::test_support::admission(),
    };
    assert_eq!(
        replay
            .bind_workspace_root(command("owner", 3), retry)
            .await
            .unwrap()
            .new_version,
        2
    );
}

#[tokio::test]
async fn store_rejects_a_verified_claim_for_another_runtime_authority_without_mutation() {
    let (_directory, path, store) = store();
    let workspace = WORKSPACE.parse().unwrap();
    create_workspace(store.clone(), workspace).await;
    let foreign = RootAdmissionVerificationContext::new(
        RootAdmissionVerificationContext::authority_digest_for("foreign-runtime"),
        [2; 16],
        1,
        RootAdmissionVerificationContext::principal_digest_for("owner"),
        3,
        1,
        100,
    )
    .unwrap();
    let keys = barrier::keys();
    let admission = barrier::issue(&keys, foreign.clone(), workspace, 71, 200, 71);
    let foreign_host = barrier::authenticated_host(
        store.clone(),
        barrier::MutableAuthority::new(foreign),
        &keys,
        None,
    );
    let before = barrier::database_state(&path);
    let request = BindWorkspaceRootCommand {
        workspace_id: workspace,
        expected_version: 1,
        root_admission: admission,
    };
    assert_eq!(
        foreign_host
            .bind_workspace_root(command("owner", 71), request)
            .await,
        Err(ProjectWorkspaceHostError::Forbidden)
    );
    let query = host(
        store.clone(),
        admission_context(),
        claims(admission_context(), workspace, 72, 200),
    );
    assert_eq!(
        query
            .get_workspace(
                ProjectQueryContext {
                    principal: ApiPrincipalId::new("owner").unwrap(),
                },
                workspace
            )
            .await
            .unwrap()
            .version,
        1
    );
    assert_eq!(barrier::database_state(&path), before);
}
