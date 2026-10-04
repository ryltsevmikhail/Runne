use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use super::super::{PreparedProviderRecord, SqliteProviderDispatchStore};
pub(super) use super::authority_row_test_support::authority_row;
use super::{
    ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig, SqliteProviderExecutionStore,
};
use runne_application::provider::{ProviderAuthorityIssueRequest, ProviderLeaseBindingKind};
use runne_provider::{
    CredentialLease, CredentialVersionRef, ModelRef, PrepareCredentialVersion,
    PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderCredentialVersionStore, ProviderId,
};

type OnlineCredentialSetup =
    Box<dyn FnOnce(&crate::provider::SqliteProviderCredentialLifecycleStore)>;

pub(super) struct TestClock {
    now: AtomicI64,
    reads: AtomicUsize,
    step_at: AtomicUsize,
    step_to: AtomicI64,
}

pub(super) fn configured_connection(path: &Path) -> crate::schema::ManagedConnection {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    if path.exists() {
        crate::schema::reopen_managed_connection_validated(
            path,
            crate::schema::ConnectionMode::ValidatedReopen,
            |_| Ok(()),
        )
        .unwrap()
    } else {
        crate::schema::open_managed_connection(path, crate::schema::ConnectionMode::Writer).unwrap()
    }
}

impl TestClock {
    pub(super) fn set(&self, now: i64) {
        self.now.store(now, Ordering::SeqCst);
    }

    pub(super) fn read_count(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    pub(super) fn step_on_read(&self, read: usize, now: i64) {
        self.step_to.store(now, Ordering::SeqCst);
        self.step_at.store(read, Ordering::SeqCst);
    }

    fn get(&self) -> i64 {
        let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if self
            .step_at
            .compare_exchange(read, usize::MAX, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.now
                .store(self.step_to.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        self.now.load(Ordering::SeqCst)
    }
}

pub(super) struct Fixture {
    pub(super) directory: tempfile::TempDir,
    pub(super) path: PathBuf,
    pub(super) clock: Arc<TestClock>,
    pub(super) store: SqliteProviderExecutionStore,
    pub(super) config: ProviderRuntimeAuthorityConfig,
    launch: OnceLock<crate::provider::ProviderRuntimeLaunchCapability>,
}

impl Fixture {
    pub(super) fn new(now: i64) -> Self {
        Self::construct(now, None).0
    }

    pub(super) fn new_with_online_credentials(
        now: i64,
        setup: impl FnOnce(&crate::provider::SqliteProviderCredentialLifecycleStore) + 'static,
    ) -> (
        Self,
        crate::provider::SqliteProviderCredentialLifecycleStore,
    ) {
        let (fixture, lifecycle) = Self::construct(now, Some(Box::new(setup)));
        (
            fixture,
            lifecycle.expect("requested online credential fixture"),
        )
    }

    fn construct(
        now: i64,
        online_setup: Option<OnlineCredentialSetup>,
    ) -> (
        Self,
        Option<crate::provider::SqliteProviderCredentialLifecycleStore>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir(&daemon).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = daemon.join("provider-v14.sqlite");
        let lifecycle = online_setup.as_ref().map(|_| {
            crate::provider::credential_lifecycle::online_claim_test_support::open_test_store(
                &path, now,
            )
        });
        if let (Some(setup), Some(lifecycle)) = (online_setup, lifecycle.as_ref()) {
            setup(lifecycle);
        }
        let clock = Arc::new(TestClock {
            now: AtomicI64::new(now),
            reads: AtomicUsize::new(0),
            step_at: AtomicUsize::new(usize::MAX),
            step_to: AtomicI64::new(now),
        });
        let captured = Arc::clone(&clock);
        let store = SqliteProviderExecutionStore::open_with_connection_and_now(
            path.to_str().unwrap(),
            configured_connection(&path),
            Arc::new(move || captured.get()),
        )
        .unwrap();
        (
            Self {
                directory,
                path,
                clock,
                store,
                config: config(),
                launch: OnceLock::new(),
            },
            lifecycle,
        )
    }

    pub(super) fn install(&self) {
        let launch = self.store.activate_runtime_launch(&self.config).unwrap();
        self.launch.set(launch).ok().unwrap();
        super::online_proof_test_support::arm(&self.store);
    }

    pub(super) fn launch(&self) -> &crate::provider::ProviderRuntimeLaunchCapability {
        self.launch.get().expect("fixture runtime launch is active")
    }

    pub(super) fn activate(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> crate::provider::ProviderRuntimeLaunchCapability {
        self.store.activate_runtime_launch(config).unwrap()
    }

    pub(super) fn issue(
        &self,
        discriminator: u8,
    ) -> Result<ProviderAuthorityIssueOutcome, runne_application::provider::ProviderAdmissionError>
    {
        self.issue_with(self.launch(), discriminator)
    }

    pub(super) fn issue_with(
        &self,
        launch: &crate::provider::ProviderRuntimeLaunchCapability,
        discriminator: u8,
    ) -> Result<ProviderAuthorityIssueOutcome, runne_application::provider::ProviderAdmissionError>
    {
        let request = prepare_request(launch, &self.path, discriminator);
        self.store.issue(launch, &request)
    }

    pub(super) fn credential(
        &self,
    ) -> (
        super::super::SqliteProviderCredentialLifecycleStore,
        super::super::CredentialDispatchBinding,
    ) {
        let lifecycle = super::super::SqliteProviderCredentialLifecycleStore::open_connection_at(
            configured_connection(&self.path),
            self.clock.get(),
        )
        .unwrap();
        let provider = ProviderId::new("fixture-provider").unwrap();
        let reference = CredentialVersionRef::new(provider.clone(), 1).unwrap();
        let lease = CredentialLease::new(reference.clone(), [1; 16], 1_600, 13).unwrap();
        let _ = lifecycle.create_prepared(PrepareCredentialVersion::new(reference));
        let _ = lifecycle.activate(lease);
        let binding = lifecycle
            .authorize_active(&provider, [1; 16], 13, self.clock.get())
            .unwrap();
        (lifecycle, binding)
    }
}

pub(super) fn config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".into(),
        owner_id: "owner-1".into(),
        scope: "provider.dispatch".into(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "capability-1".into(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-1".into(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

pub(super) fn prepare_request(
    launch: &crate::provider::ProviderRuntimeLaunchCapability,
    path: &Path,
    discriminator: u8,
) -> ProviderAuthorityIssueRequest {
    prepare_request_for_provider(launch, path, discriminator, "fixture-provider")
}

pub(super) fn prepare_request_for_provider(
    launch: &crate::provider::ProviderRuntimeLaunchCapability,
    path: &Path,
    discriminator: u8,
    provider: &str,
) -> ProviderAuthorityIssueRequest {
    let (conversation_id, taskrun_id, execution_attempt_id) =
        super::canonical_started_test_support::seed(path, discriminator);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([discriminator; 16]),
        ModelRef::new(ProviderId::new(provider).unwrap(), "fixture-model", "v1").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [2; 32],
    };
    let path_text = path.to_str().unwrap();
    SqliteProviderDispatchStore::open_with_connection(path_text, configured_connection(path))
        .unwrap()
        .persist_prepared(launch, &record)
        .unwrap();
    ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new(provider).unwrap(),
        principal_id: "principal-1".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id,
        prepared: ContractPreparedProviderRecord {
            call_id: record.call_id,
            call_digest_version: record.call_digest_version,
            prepared_digest: record.prepared_digest,
            render_digest: record.render_digest,
            profile_digest: record.profile_digest,
        },
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: format!("provider-v14-{discriminator}"),
    }
}
