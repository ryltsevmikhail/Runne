use std::collections::HashMap;
use std::path::{Path, PathBuf};

use runne_application::provider::{
    ProviderAuthorityIssueRequest, ProviderExecutionStore, ProviderOperationalTelemetrySource,
};
use runne_provider::{
    CredentialLease, CredentialVersionRef, ModelRef, PrepareCredentialVersion,
    PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderCredentialVersionStore, ProviderId,
};
use runne_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
    ProviderRuntimeLaunchCapability, SqliteProviderCredentialLifecycleStore,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
use runne_store::schema::{
    ConnectionMode, ManagedConnection, open_managed_connection, reopen_managed_connection_validated,
};

mod fixture_setup;
use fixture_setup::{arm_online_proof, config, scope};

#[path = "../support/provider_taskrun_start.rs"]
mod provider_taskrun_start;
#[path = "../support/validated_reopen.rs"]
mod validated_reopen;

const OBSERVED_AT: u64 = 1_000_000;

pub(super) struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
    store: SqliteProviderExecutionStore,
    launch: ProviderRuntimeLaunchCapability,
    taskrun_receipts: HashMap<u8, runne_application::ports::TextGenerationReceipt>,
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
        let receipts = provider_taskrun_start::begin_many(
            path.to_str().unwrap(),
            [1; 16],
            "principal-1",
            "operational telemetry fixture prompt",
            &(1..=23).collect::<Vec<_>>(),
        );
        let taskrun_receipts = (1..=23).zip(receipts).collect::<HashMap<_, _>>();
        let store = SqliteProviderExecutionStore::open_with_connection(
            path.to_str().unwrap(),
            configured_connection(&path),
        )
        .unwrap();
        let launch = store.activate_runtime_launch(&config()).unwrap();
        arm_online_proof(&store);
        Self {
            directory,
            path,
            store,
            launch,
            taskrun_receipts,
        }
    }

    pub(super) fn connection(&self) -> ManagedConnection {
        let _ = &self.directory;
        configured_connection(&self.path)
    }

    pub(super) fn issue(&self, discriminator: u8) {
        let record = record(&self.launch, &self.path, discriminator);
        let request = request(
            record,
            discriminator,
            self.taskrun_receipts
                .get(&discriminator)
                .unwrap_or_else(|| {
                    panic!(
                        "missing TaskRun receipt {discriminator}; stored keys {:?}",
                        self.taskrun_receipts.keys()
                    )
                }),
        );
        assert!(matches!(
            self.store.issue(&self.launch, &request).unwrap(),
            ProviderAuthorityIssueOutcome::Winner(_)
        ));
    }

    pub(super) fn issue_and_start_effect(&self, discriminator: u8) {
        let record = record(&self.launch, &self.path, discriminator);
        let request = request(
            record,
            discriminator,
            self.taskrun_receipts
                .get(&discriminator)
                .unwrap_or_else(|| {
                    panic!(
                        "missing TaskRun receipt {discriminator}; stored keys {:?}",
                        self.taskrun_receipts.keys()
                    )
                }),
        );
        let ProviderAuthorityIssueOutcome::Winner(admission) =
            self.store.issue(&self.launch, &request).unwrap()
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

fn record(
    launch: &ProviderRuntimeLaunchCapability,
    path: &Path,
    discriminator: u8,
) -> PreparedProviderRecord {
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
    .persist_prepared(launch, &record)
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

fn request(
    record: PreparedProviderRecord,
    discriminator: u8,
    started: &runne_application::ports::TextGenerationReceipt,
) -> ProviderAuthorityIssueRequest {
    ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new("fixture-provider").unwrap(),
        principal_id: "principal-1".into(),
        conversation_id: started.conversation_id,
        taskrun_id: started.taskrun_id,
        execution_attempt_id: started.attempt_id,
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
