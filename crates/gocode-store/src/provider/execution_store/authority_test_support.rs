use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use super::super::{PreparedProviderRecord, SqliteProviderDispatchStore};
use super::{
    ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig, SqliteProviderExecutionStore,
};
use gocode_application::provider::{ProviderAuthorityIssueRequest, ProviderLeaseBindingKind};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    CredentialLease, CredentialVersionRef, ModelRef, PrepareCredentialVersion,
    PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderCredentialVersionStore, ProviderId,
};
use rusqlite::Connection;

pub(super) struct TestClock(AtomicI64);

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
        self.0.store(now, Ordering::SeqCst);
    }

    fn get(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub(super) struct Fixture {
    pub(super) directory: tempfile::TempDir,
    pub(super) path: PathBuf,
    pub(super) clock: Arc<TestClock>,
    pub(super) store: SqliteProviderExecutionStore,
    pub(super) config: ProviderRuntimeAuthorityConfig,
}

impl Fixture {
    pub(super) fn new(now: i64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let daemon = directory.path().join("gocode-daemon");
        std::fs::create_dir(&daemon).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = daemon.join("provider-v14.sqlite");
        let clock = Arc::new(TestClock(AtomicI64::new(now)));
        let captured = Arc::clone(&clock);
        let store =
            SqliteProviderExecutionStore::open_with_now(&path, Arc::new(move || captured.get()))
                .unwrap();
        Self {
            directory,
            path,
            clock,
            store,
            config: config(),
        }
    }

    pub(super) fn install(&self) {
        self.store.install_runtime_authority(&self.config).unwrap();
    }

    pub(super) fn issue(
        &self,
        discriminator: u8,
    ) -> Result<ProviderAuthorityIssueOutcome, gocode_application::provider::ProviderAdmissionError>
    {
        let request = prepare_request(&self.path, discriminator);
        self.store.issue(&request)
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

pub(super) fn prepare_request(path: &Path, discriminator: u8) -> ProviderAuthorityIssueRequest {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([discriminator; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "v1",
        )
        .unwrap(),
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
        .persist_prepared(&record)
        .unwrap();
    ProviderAuthorityIssueRequest {
        principal_id: "principal-1".into(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
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

#[derive(Debug, PartialEq, Eq)]
pub(super) struct AuthorityRow {
    pub(super) capability_expires_at: i64,
    pub(super) approval_expires_at: i64,
    pub(super) state_revision: i64,
    pub(super) active: i64,
}

pub(super) fn authority_row(path: &Path) -> AuthorityRow {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT capability_expires_at, approval_expires_at, state_revision, active
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok(AuthorityRow {
                    capability_expires_at: row.get(0)?,
                    approval_expires_at: row.get(1)?,
                    state_revision: row.get(2)?,
                    active: row.get(3)?,
                })
            },
        )
        .unwrap()
}
