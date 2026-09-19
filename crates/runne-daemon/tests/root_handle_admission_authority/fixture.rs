use super::*;

use runne_api::WorkspaceId;
use runne_api::test_support::into_untrusted_admission;
use runne_application::ports::{ProjectWorkspaceRepository, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture;
use runne_domain::event::Sensitivity;
use runne_domain::id::{CommandId, DaemonInstanceId, EventLogLineageId, IdempotencyKey, ProjectId};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_platform_desktop::VerifiedRootHandle;
use runne_security::SecretBroker;
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};
use rusqlite::Connection;
use std::path::PathBuf;

pub(super) const AUTHORITY_NAME: &str = "admission-authority-test";
pub(super) const AUTHORITY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
pub(super) const SESSION: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];
pub(super) const FOREIGN_SESSION: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 9];
pub(super) const PROJECT: &str = "018f47a2-4f8c-7b52-8c35-7a3a14c2d9e1";
pub(super) const WORKSPACE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];
pub(super) const PRINCIPAL: &str = "local-owner";

pub(super) fn keys() -> ProtectedActivationKeys {
    LaunchSecret::from_bytes([9; 32])
        .expect("secret")
        .derive_keys()
}

pub(super) fn session_service(session: [u8; 16]) -> LocalSessionService {
    let stable = StableRuntimeBinding::new(
        AUTHORITY,
        ApiPrincipalId::new(PRINCIPAL).expect("principal"),
        EventLogLineageId::from_bytes([0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 2]),
        "fixture",
        [3; 32],
        [4; 32],
    )
    .expect("stable binding");
    let binding = RuntimeSessionBinding::new(
        stable,
        DaemonInstanceId::from_bytes([0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 3]),
        1,
        session,
        0,
        Sensitivity::Public,
        [5; 32],
    )
    .expect("session binding");
    LocalSessionService::new(binding, [7; 32])
}

pub(super) fn offer(
    keys: &ProtectedActivationKeys,
    workspace: WorkspaceId,
    now: u64,
) -> RootHandleTransferOffer {
    let context = RootHandleTransferContext::new(
        AUTHORITY,
        SESSION,
        1,
        10,
        11,
        1_000,
        workspace,
        1,
        [4; 16],
        now,
        now + 30_000,
    )
    .expect("transfer context");
    let authenticator = RootHandleTransferAuthenticator::from_protected_activation(keys);
    RootHandleTransferOffer::new(context, 1, &authenticator).expect("offer")
}

/// Issues an otherwise-valid signed admission without any daemon verdict.
pub(super) fn forge(
    keys: &ProtectedActivationKeys,
    context: &RootAdmissionVerificationContext,
    workspace: WorkspaceId,
    identity: [u8; 32],
    offer_digest: [u8; 32],
    nonce: [u8; 16],
    expires_at: u64,
) -> RootHandleAdmission {
    let issued = RootAdmissionAuthenticator::from_protected_activation(keys)
        .issue(
            RootAdmissionRequest::new(
                context.clone(),
                workspace,
                1,
                identity,
                offer_digest,
                nonce,
                expires_at,
            )
            .expect("admission request"),
        )
        .expect("signed admission");
    into_untrusted_admission(issued)
}

pub(super) fn claims_context(policy_version: u64, now: u64) -> RootAdmissionVerificationContext {
    RootAdmissionVerificationContext::new(
        RootAdmissionVerificationContext::authority_digest_for(AUTHORITY_NAME),
        SESSION,
        1,
        RootAdmissionVerificationContext::principal_digest_for(PRINCIPAL),
        3,
        policy_version,
        now,
    )
    .expect("claims context")
}

pub(super) fn workspace() -> WorkspaceId {
    WorkspaceId::from_bytes(WORKSPACE)
}

pub(super) fn seed_workspace(store: &StoreTransaction) {
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = PROJECT.parse::<ProjectId>().expect("project id");
    repository
        .create_project(
            PRINCIPAL,
            CommandId::from_bytes([1; 16]),
            &IdempotencyKey::new("seed-project").expect("key"),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("fixture-project".into()).expect("name"),
            ),
        )
        .expect("seed project");
    repository
        .create_workspace(
            PRINCIPAL,
            CommandId::from_bytes([2; 16]),
            &IdempotencyKey::new("seed-workspace").expect("key"),
            Workspace::create(
                workspace(),
                project_id,
                ProjectWorkspaceDisplayName::new("fixture-workspace".into()).expect("name"),
            ),
        )
        .expect("seed workspace");
}

/// Bounded durable snapshot: workspace rows plus admission/bind effects.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DurableState {
    pub(super) workspaces: Vec<(Vec<u8>, i64, i64, i64)>,
    pub(super) nonces: usize,
    pub(super) receipts: usize,
}

pub(super) fn database_state(path: &std::path::Path) -> DurableState {
    let connection = Connection::open(path).expect("database");
    let workspaces = connection
        .prepare("SELECT workspace_id, version, open, live FROM workspaces ORDER BY workspace_id")
        .expect("workspaces query")
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("workspaces rows")
        .collect::<rusqlite::Result<_>>()
        .expect("workspaces");
    let count = |sql: &str| {
        connection
            .prepare(sql)
            .expect("query")
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("rows")
            .count()
    };
    let nonces = count("SELECT nonce FROM root_admission_nonces");
    let receipts = count("SELECT command_id FROM project_workspace_command_receipts");
    DurableState {
        workspaces,
        nonces,
        receipts,
    }
}

pub(super) fn store() -> (tempfile::TempDir, PathBuf, StoreTransaction) {
    let directory = tempfile::tempdir().expect("directory");
    let runtime = directory.path().join("runtime");
    let daemon = runtime.join("runne-daemon");
    std::fs::create_dir_all(&daemon).expect("database layout");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .expect("runtime permissions");
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("daemon permissions");
    }
    let path = daemon.join("admission-authority.sqlite");
    let guard: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open(
        path.to_str().expect("database path"),
        RuntimeAuthorityId(AUTHORITY_NAME.into()),
        guard,
    )
    .expect("store");
    (directory, path, store)
}

pub(super) fn root_handle(directory: &tempfile::TempDir) -> VerifiedRootHandle {
    VerifiedRootHandle::open(&std::fs::canonicalize(directory.path()).expect("canonical root"))
        .expect("root handle")
}

/// Opens the durable trust sidecar next to the canonical store and builds the
/// single policy authority (the daemon composition, in-process).
pub(super) fn trust_composition(
    canonical: &std::path::Path,
) -> (
    Arc<runne_store::ProjectTrustStore>,
    Arc<runne_security::project_trust_policy::ProjectTrustPolicyAuthority>,
) {
    let store =
        Arc::new(runne_store::ProjectTrustStore::open(canonical, AUTHORITY).expect("sidecar"));
    let authority = Arc::new(
        runne_security::project_trust_policy::ProjectTrustPolicyAuthority::new(store.clone())
            .with_byte_inspection(Arc::new(
                runne_security::SecretBroker::new().prohibited_content_guard(),
            )),
    );
    (store, authority)
}

/// Grants the seed project the Trusted state through the durable store port.
pub(super) fn grant_trusted(store: &runne_store::ProjectTrustStore) {
    use runne_application::project_trust::{
        ProjectTrustPersistence, ProjectTrustStatus, TrustToken,
    };
    let epoch = store.instance_epoch().expect("epoch");
    store
        .commit(
            project_trust_id(),
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(epoch, 0),
        )
        .expect("grant trusted");
}

pub(super) fn project_trust_id() -> runne_application::project_trust::ProjectTrustProjectId {
    runne_application::project_trust::ProjectTrustProjectId::from_bytes(
        *PROJECT.parse::<ProjectId>().expect("project id").as_bytes(),
    )
}

pub(super) fn fixture(
    store: StoreTransaction,
    sessions: Arc<Mutex<LocalSessionService>>,
) -> RootAdmissionAuthorityFixture {
    RootAdmissionAuthorityFixture::new(
        &keys(),
        ProjectWorkspaceStore::from_store(store),
        AUTHORITY_NAME.into(),
        sessions,
    )
}

pub(super) fn fixture_with_trust(
    store: StoreTransaction,
    sessions: Arc<Mutex<LocalSessionService>>,
    trust: Arc<runne_security::project_trust_policy::ProjectTrustPolicyAuthority>,
) -> RootAdmissionAuthorityFixture {
    RootAdmissionAuthorityFixture::new_with_trust(
        &keys(),
        ProjectWorkspaceStore::from_store(store),
        AUTHORITY_NAME.into(),
        sessions,
        trust,
    )
}
