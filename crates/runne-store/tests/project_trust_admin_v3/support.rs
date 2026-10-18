use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::project_trust::{
    ManagedEffectDecision, ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot,
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus, TrustToken,
    admin::{
        AdminError, ManagedPolicyCommandV1, ManagedPolicyConsentBindingV1,
        ManagedPolicyConsentVerifierV1, PolicyAdminAuthoritySource, PolicyAdminAuthorityVerifier,
        PolicyAdminBootstrapEvidence, PolicyAdminBootstrapVerifier, PolicyAdminSessionBinding,
        VerifiedPolicyAdminBootstrap, verify_policy_admin_bootstrap, with_verified_policy_admin,
    },
};
use runne_domain::{event::Sensitivity, id::EventLogLineageId};
use runne_store::ProjectTrustStore;

pub const AUTHORITY: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1];
pub const PROJECT: [u8; 16] = [0x71; 16];
const LINEAGE: &str = "018f2e3a-7000-7000-8000-000000000003";
const DAEMON: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2];

pub fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

pub fn session(generation: u64, epoch: u64, deadline: i64) -> PolicyAdminSessionBinding {
    session_as("owner", generation, epoch, deadline)
}

pub fn session_as(
    principal: &str,
    generation: u64,
    epoch: u64,
    deadline: i64,
) -> PolicyAdminSessionBinding {
    let runtime = RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            AUTHORITY,
            ApiPrincipalId::new(principal).unwrap(),
            LINEAGE.parse::<EventLogLineageId>().unwrap(),
            "client/2",
            [0x33; 32],
            [0x44; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(DAEMON),
        generation,
        [generation as u8; 16],
        epoch,
        Sensitivity::Internal,
        [0x66; 32],
    )
    .unwrap();
    PolicyAdminSessionBinding::new(
        runtime,
        [generation as u8 + 0x70; 16],
        [generation as u8 + 0x80; 32],
        epoch,
        deadline,
    )
}

pub fn evidence(binding: PolicyAdminSessionBinding) -> PolicyAdminBootstrapEvidence {
    PolicyAdminBootstrapEvidence::new(binding, [0x99; 32], [0xaa; 32])
}

#[derive(Default)]
pub struct TestBootstrap;

impl PolicyAdminBootstrapVerifier for TestBootstrap {
    fn verify_retained_protected_bootstrap(
        &self,
        proof: &PolicyAdminBootstrapEvidence,
    ) -> Result<(), AdminError> {
        if proof.installation_provenance() == &[0x99; 32]
            && proof.retained_bootstrap_handle() == &[0xaa; 32]
        {
            Ok(())
        } else {
            Err(AdminError::Rejected)
        }
    }
}

pub struct TestSessionOwner(pub Mutex<PolicyAdminBootstrapEvidence>);

impl PolicyAdminAuthoritySource for TestSessionOwner {
    fn with_current_evidence(
        &self,
        expected: &PolicyAdminSessionBinding,
        callback: &mut dyn FnMut(&PolicyAdminBootstrapEvidence) -> Result<(), AdminError>,
    ) -> Result<(), AdminError> {
        let evidence = self
            .0
            .lock()
            .map_err(|_| AdminError::AuthorityUnavailable)?;
        if evidence.binding() != expected {
            return Err(AdminError::AuthorityUnavailable);
        }
        callback(&evidence)
    }
}

pub struct AdminFixture {
    pub bootstrap_verifier: TestBootstrap,
    pub session_owner: TestSessionOwner,
}

pub struct AcceptConsent;

impl ManagedPolicyConsentVerifierV1 for AcceptConsent {
    fn verify(
        &self,
        binding: &ManagedPolicyConsentBindingV1,
        _proof_bytes: &[u8],
    ) -> Result<[u8; 16], AdminError> {
        Ok(*binding.challenge_id())
    }
}

impl AdminFixture {
    pub fn new(binding: PolicyAdminSessionBinding) -> Self {
        Self {
            bootstrap_verifier: TestBootstrap,
            session_owner: TestSessionOwner(Mutex::new(evidence(binding))),
        }
    }

    pub fn update(&self, binding: PolicyAdminSessionBinding) {
        *self.session_owner.0.lock().unwrap() = evidence(binding);
    }

    pub fn verifier(&self) -> PolicyAdminAuthorityVerifier<'_> {
        PolicyAdminAuthorityVerifier::new(&self.bootstrap_verifier, &self.session_owner)
    }

    pub fn with<R>(
        &self,
        binding: &PolicyAdminSessionBinding,
        action: impl for<'a> FnOnce(
            &'a runne_application::project_trust::admin::CurrentPolicyAdmin<'a>,
        ) -> Result<R, AdminError>,
    ) -> Result<R, AdminError> {
        with_verified_policy_admin(&self.verifier(), binding, action)
    }

    pub fn bootstrap(&self, binding: &PolicyAdminSessionBinding) -> VerifiedPolicyAdminBootstrap {
        verify_policy_admin_bootstrap(&evidence(binding.clone()), &self.bootstrap_verifier).unwrap()
    }
}

pub fn canonical(root: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let daemon = root.join("runtime/daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    std::fs::set_permissions(root.join("runtime"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    daemon.join(name)
}

pub fn trusted_store(root: &Path, name: &str) -> (PathBuf, ProjectTrustStore) {
    let path = canonical(root, name);
    let store = ProjectTrustStore::open(&path, AUTHORITY).unwrap();
    let epoch = store.instance_epoch().unwrap();
    store
        .commit(
            ProjectTrustProjectId::from_bytes(PROJECT),
            ProjectTrustStatus::Trusted,
            13,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    (path, store)
}

pub fn register(
    store: &ProjectTrustStore,
    fixture: &AdminFixture,
    binding: &PolicyAdminSessionBinding,
) {
    let bootstrap = fixture.bootstrap(binding);
    fixture
        .with(binding, |current| store.register_admin(current, &bootstrap))
        .unwrap();
}

pub fn snapshot(store: &ProjectTrustStore) -> ProjectTrustEffectPolicySnapshot {
    store
        .acquire_effect_lease(ProjectTrustProjectId::from_bytes(PROJECT))
        .unwrap()
        .snapshot()
        .unwrap()
}

pub fn rules() -> ManagedEffectPolicyV1 {
    ManagedEffectPolicyV1::new(
        1,
        [
            ManagedEffectDecision::Ask,
            ManagedEffectDecision::Deny,
            ManagedEffectDecision::Allow,
            ManagedEffectDecision::Ask,
            ManagedEffectDecision::Deny,
            ManagedEffectDecision::Allow,
        ],
    )
}

pub fn request(
    binding: &PolicyAdminSessionBinding,
    snapshot: ProjectTrustEffectPolicySnapshot,
    id: [u8; 16],
    key: &str,
    generation: u64,
) -> ManagedPolicyCommandV1 {
    ManagedPolicyCommandV1::new(
        id,
        key,
        ProjectTrustProjectId::from_bytes(PROJECT),
        snapshot,
        rules(),
        generation,
        binding,
        1,
    )
    .unwrap()
}
