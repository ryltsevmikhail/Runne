use std::path::{Path, PathBuf};

use gocode_application::provider::{
    ProviderAuthorityIssueRequest, ProviderLeaseBindingKind, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySource,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderId,
};
use gocode_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
use rusqlite::Connection;

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
        let path = directory.path().join(file_name);
        let store = SqliteProviderExecutionStore::open(&path).unwrap();
        store.install_runtime_authority(&config()).unwrap();
        Self {
            directory,
            path,
            store,
        }
    }

    pub(super) fn connection(&self) -> Connection {
        let _ = &self.directory;
        let connection = Connection::open(&self.path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
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
        self.store.start_effect(admission.claim()).unwrap();
    }

    pub(super) fn read(
        &self,
    ) -> Result<
        gocode_application::provider::ProviderDurableOperationalTelemetry,
        gocode_application::provider::ProviderOperationalTelemetrySourceError,
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

fn configured_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
        )
        .unwrap();
    #[cfg(target_os = "macos")]
    connection.execute_batch("PRAGMA fullfsync = ON;").unwrap();
    connection
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
