//! T1 wiring harness: the real daemon root-admission authority composed with
//! the runtime-owned durable trust sidecar in one process.
//!
//! Trust grants go exclusively through the durable store port (the same
//! composition API the daemon uses); no client-supplied trusted flag exists.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_api::{
    LaunchSecret, ProtectedActivationKeys, RootHandleTransferAuthenticator,
    RootHandleTransferContext, RootHandleTransferOffer, RootAdmissionVerificationContext,
    RuntimeSessionBinding, StableRuntimeBinding, WorkspaceId,
};
use runne_application::local_session::LocalSessionService;
use runne_application::ports::{ProjectWorkspaceRepository, RuntimeAuthorityId};
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
    TrustToken,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture;
use runne_domain::event::Sensitivity;
use runne_domain::id::{CommandId, DaemonInstanceId, EventLogLineageId, IdempotencyKey, ProjectId};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_security::SecretBroker;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::store::StoreTransaction;
use runne_store::{ProjectTrustStore, ProjectWorkspaceStore};

pub(super) const AUTHORITY_NAME: &str = "t1-trust-wiring";
/// Sidecar authority identity (daemon passes `bootstrap.authority_id` here).
pub(super) const SIDECAR_AUTHORITY: [u8; 16] =
    [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
pub(super) const SESSION: [u8; 16] =
    [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];
pub(super) const PROJECT: &str = "018f47a2-4f8c-7b52-8c35-7a3a14c2d9e1";
pub(super) const PROJECT2: &str = "018f47a2-4f8c-7b52-8c35-7a3a14c2d9e2";
pub(super) const WORKSPACE: [u8; 16] =
    [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];
pub(super) const WORKSPACE2: [u8; 16] =
    [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 7];
pub(super) const PRINCIPAL: &str = "local-owner";
/// Synthetic canary marker only (never a real secret).
pub(super) const CANARY: &str = "RUNNE_T1_FAKE_CANARY_zq71";

pub(super) fn real_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

pub(super) fn keys() -> ProtectedActivationKeys {
    LaunchSecret::from_bytes([9; 32])
        .expect("secret")
        .derive_keys()
}

pub(super) fn sessions() -> Arc<Mutex<LocalSessionService>> {
    let stable = StableRuntimeBinding::new(
        SIDECAR_AUTHORITY,
        runne_api::ApiPrincipalId::new(PRINCIPAL).expect("principal"),
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
        SESSION,
        0,
        Sensitivity::Public,
        [5; 32],
    )
    .expect("session binding");
    Arc::new(Mutex::new(LocalSessionService::new(binding, [7; 32])))
}

pub(super) fn workspace() -> WorkspaceId {
    WorkspaceId::from_bytes(WORKSPACE)
}

pub(super) fn workspace2() -> WorkspaceId {
    WorkspaceId::from_bytes(WORKSPACE2)
}

pub(super) fn project_trust_id(raw: &str) -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes(*raw.parse::<ProjectId>().expect("project id").as_bytes())
}

pub(super) fn offer(keys: &ProtectedActivationKeys, ws: WorkspaceId, now: u64) -> RootHandleTransferOffer {
    let context = RootHandleTransferContext::new(
        SIDECAR_AUTHORITY,
        SESSION,
        1,
        10,
        11,
        1_000,
        ws,
        1,
        [4; 16],
        now,
        now + 30_000,
    )
    .expect("transfer context");
    let authenticator = RootHandleTransferAuthenticator::from_protected_activation(keys);
    RootHandleTransferOffer::new(context, 1, &authenticator).expect("offer")
}

pub(super) fn claims_context(now: u64) -> RootAdmissionVerificationContext {
    RootAdmissionVerificationContext::new(
        RootAdmissionVerificationContext::authority_digest_for(AUTHORITY_NAME),
        SESSION,
        1,
        RootAdmissionVerificationContext::principal_digest_for(PRINCIPAL),
        3,
        RootAdmissionAuthorityFixture::pinned_policy_version(),
        now,
    )
    .expect("claims context")
}

pub(super) fn store() -> (tempfile::TempDir, PathBuf, StoreTransaction) {
    let directory = tempfile::tempdir().expect("directory");
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).expect("database layout");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("daemon permissions");
    }
    let path = daemon.join("trust-wiring.sqlite");
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

pub(super) fn seed_projects(store: &StoreTransaction) {
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let mut index = 0u8;
    for (raw, ws) in [(PROJECT, workspace()), (PROJECT2, workspace2())] {
        index += 1;
        let project_id = raw.parse::<ProjectId>().expect("project id");
        repository
            .create_project(
                PRINCIPAL,
                CommandId::from_bytes([index; 16]),
                &IdempotencyKey::new(format!("seed-{raw}")).expect("key"),
                Project::create(
                    project_id,
                    ProjectWorkspaceDisplayName::new("fixture".into()).expect("name"),
                ),
            )
            .expect("seed project");
        repository
            .create_workspace(
                PRINCIPAL,
                CommandId::from_bytes([index + 0x20; 16]),
                &IdempotencyKey::new(format!("seed-ws-{raw}")).expect("key"),
                Workspace::create(
                    ws,
                    project_id,
                    ProjectWorkspaceDisplayName::new("fixture-ws".into()).expect("name"),
                ),
            )
            .expect("seed workspace");
    }
}

/// Opens the durable trust sidecar next to the canonical store and builds the
/// single policy authority over it (the daemon composition, in-process).
pub(super) fn trust_composition(
    canonical: &Path,
) -> (Arc<ProjectTrustStore>, Arc<ProjectTrustPolicyAuthority>) {
    let store = Arc::new(ProjectTrustStore::open(canonical, SIDECAR_AUTHORITY).expect("sidecar"));
    let authority = Arc::new(
        ProjectTrustPolicyAuthority::new(store.clone())
            .with_byte_inspection(Arc::new(SecretBroker::new().prohibited_content_guard())),
    );
    (store, authority)
}

pub(super) fn grant_trusted(
    store: &ProjectTrustStore,
    project: ProjectTrustProjectId,
) -> ProjectTrustRecord {
    let epoch = store.instance_epoch().expect("epoch");
    store
        .commit(project, ProjectTrustStatus::Trusted, 0, TrustToken::new(epoch, 0))
        .expect("grant")
}

pub(super) fn commit_status(
    store: &ProjectTrustStore,
    project: ProjectTrustProjectId,
    status: ProjectTrustStatus,
    mask: u32,
    expected: TrustToken,
) -> ProjectTrustRecord {
    store
        .commit(project, status, mask, expected)
        .expect("trust commit")
}

pub(super) fn load_record(
    store: &ProjectTrustStore,
    project: ProjectTrustProjectId,
) -> ProjectTrustRecord {
    store.load(project).expect("trust load")
}

pub(super) fn root_handle(directory: &tempfile::TempDir) -> runne_platform_desktop::VerifiedRootHandle {
    runne_platform_desktop::VerifiedRootHandle::open(&std::fs::canonicalize(directory.path()).expect("canonical"))
        .expect("root handle")
}

/// Workspace fixture data: one non-secret canary file plus frozen deny names.
pub(super) fn seed_workspace_files(directory: &tempfile::TempDir) {
    let root = directory.path();
    std::fs::create_dir_all(root.join("notes")).expect("notes dir");
    std::fs::create_dir_all(root.join("keys")).expect("keys dir");
    std::fs::write(root.join("notes/plan.md"), format!("plan {CANARY}\n")).expect("plan");
    std::fs::write(root.join("README.md"), "readme\n").expect("readme");
    std::fs::write(root.join(".env"), format!("TOKEN={CANARY}\n")).expect("env canary");
    std::fs::write(root.join("keys/host.key"), format!("{CANARY}\n")).expect("key canary");
}

pub(super) fn fixture_with_trust(
    store: &StoreTransaction,
    trust: Arc<ProjectTrustPolicyAuthority>,
    sessions: Arc<Mutex<LocalSessionService>>,
) -> RootAdmissionAuthorityFixture {
    RootAdmissionAuthorityFixture::new_with_trust(
        &keys(),
        ProjectWorkspaceStore::from_store(store.clone()),
        AUTHORITY_NAME.into(),
        sessions,
        trust,
    )
}

/// Issues and verifies a root admission so the gateway holds an active root.
pub(super) fn bind_active_root(
    fixture: &RootAdmissionAuthorityFixture,
    directory: &tempfile::TempDir,
    ws: WorkspaceId,
    now: u64,
) {
    let issued = fixture
        .issue(&offer(&keys(), ws, now), root_handle(directory), now)
        .expect("issue admission");
    fixture.verify(issued.admission).expect("verify activates root");
}
