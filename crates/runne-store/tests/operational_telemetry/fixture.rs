use std::path::{Path, PathBuf};

use runne_application::provider::{
    ProviderAuthorityIssueRequest, ProviderLeaseBindingKind, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySource,
};
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    CredentialLease, CredentialVersionRef, ModelRef, PrepareCredentialVersion,
    PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderCredentialVersionStore, ProviderId,
};
use runne_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
    SqliteProviderCredentialLifecycleStore, SqliteProviderDispatchStore,
    SqliteProviderExecutionStore,
};
use runne_store::schema::{
    ConnectionMode, ManagedConnection, open_managed_connection, reopen_managed_connection_validated,
};
const OBSERVED_AT: u64 = 1_000_000;

pub(super) struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
    store: SqliteProviderExecutionStore,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::new_with_name("telemetry.sqlite")
    }

    pub(super) fn new_with_name(file_name: &str) -> Self {
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
        let path = daemon.join(file_name);
        let store = SqliteProviderExecutionStore::open(&path).unwrap();
        store.install_runtime_authority(&config()).unwrap();
        Self {
            directory,
            path,
            store,
        }
    }

    pub(super) fn connection(&self) -> ManagedConnection {
        let _ = &self.directory;
        configured_connection(&self.path)
    }

    pub(super) fn issue(&self, discriminator: u8) {
        let record = record(&self.path, discriminator);
        let request = request(record, discriminator);
        assert!(matches!(
            self.store.issue(&request).unwrap(),
            ProviderAuthorityIssueOutcome::Winner(_)
        ));
    }

    pub(super) fn issue_and_start_effect(&self, discriminator: u8) {
        let record = record(&self.path, discriminator);
        let request = request(record, discriminator);
        let ProviderAuthorityIssueOutcome::Winner(admission) = self.store.issue(&request).unwrap()
        else {
            panic!("expected a new admission");
        };
        let credential = SqliteProviderCredentialLifecycleStore::open_connection_at(
            configured_connection(&self.path),
            100,
        )
        .unwrap();
        let reference =
            CredentialVersionRef::new(ProviderId::new("fixture-provider").unwrap(), 1).unwrap();
        let _ = credential.create_prepared(PrepareCredentialVersion::new(reference.clone()));
        let _ = credential
            .activate(CredentialLease::new(reference.clone(), [1; 16], i64::MAX, 13).unwrap());
        let binding = credential
            .authorize_active(reference.provider(), [1; 16], 13, 100)
            .unwrap();
        self.store
            .start_effect(admission.claim(), &binding)
            .unwrap();
    }

    pub(super) fn read(
        &self,
    ) -> Result<
        runne_application::provider::ProviderDurableOperationalTelemetry,
        runne_application::provider::ProviderOperationalTelemetrySourceError,
    > {
        self.store.read_durable_operational_telemetry(scope())
    }
}

fn scope() -> ProviderOperationalTelemetryScope {
    ProviderOperationalTelemetryScope::new([1; 16], 7, 11, 13, [2; 32], OBSERVED_AT).unwrap()
}

fn config() -> ProviderRuntimeAuthorityConfig {
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

fn record(path: &Path, discriminator: u8) -> PreparedProviderRecord {
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
    SqliteProviderDispatchStore::open_with_connection(
        path.to_str().unwrap(),
        configured_connection(path),
    )
    .unwrap()
    .persist_prepared(&record)
    .unwrap();
    record
}

fn configured_connection(path: &Path) -> ManagedConnection {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    if path.exists() {
        reopen_managed_connection_validated(path, ConnectionMode::ValidatedReopen, |connection| {
            let version: i64 = connection.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )?;
            if version == runne_store::schema::CURRENT_SCHEMA_VERSION {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        })
        .unwrap()
    } else {
        open_managed_connection(path, ConnectionMode::Writer).unwrap()
    }
}

fn request(record: PreparedProviderRecord, discriminator: u8) -> ProviderAuthorityIssueRequest {
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
        provider_idempotency_key: format!("provider-{discriminator}"),
    }
}
