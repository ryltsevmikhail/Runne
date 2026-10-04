use runne_application::provider::{ProviderAdmissionError, ProviderAuthorityIssueRequest};
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderDispatchClaim, ProviderId,
};
use runne_store::provider::{
    CredentialDispatchBinding, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderDispatchState, ProviderRuntimeAuthorityConfig, SqliteProviderCredentialLifecycleStore,
    SqliteProviderExecutionStore,
};
use rusqlite::{Connection, params};
use std::cell::RefCell;

struct ArmedProviderTestDatabase {
    database: validated_reopen::ProviderTestDatabase,
    execution: SqliteProviderExecutionStore,
    launch: RefCell<runne_store::provider::ProviderRuntimeLaunchCapability>,
    taskrun_receipts:
        std::collections::HashMap<u8, runne_application::ports::TextGenerationReceipt>,
}

impl ArmedProviderTestDatabase {
    fn new(name: &str) -> Self {
        let database = validated_reopen::ProviderTestDatabase::new(name);
        let mut discriminators = (1..=19).collect::<Vec<_>>();
        discriminators.push(81);
        let receipts = crate::online_stream_fixture::begin_taskruns(
            &database,
            [1; 16],
            "principal-1",
            "provider recovery audit fixture",
            &discriminators,
        );
        let taskrun_receipts = discriminators.into_iter().zip(receipts).collect();
        let execution = database.execution();
        let config = runtime_config::runtime_config();
        let launch = execution.activate_runtime_launch(&config).unwrap();
        crate::online_proof::arm(&execution, config.database_generation);
        Self {
            database,
            execution,
            launch: RefCell::new(launch),
            taskrun_receipts,
        }
    }

    fn execution(&self) -> SqliteProviderExecutionStore {
        let execution = self.database.execution();
        crate::online_proof::arm(&execution, 7);
        execution
    }

    fn issue(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssueOutcome, ProviderAdmissionError> {
        self.execution.issue(&self.launch.borrow(), request)
    }

    fn activate_runtime_launch(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
        let launch = self.execution().activate_runtime_launch(config)?;
        *self.launch.borrow_mut() = launch;
        Ok(())
    }
}

impl std::ops::Deref for ArmedProviderTestDatabase {
    type Target = validated_reopen::ProviderTestDatabase;

    fn deref(&self) -> &Self::Target {
        &self.database
    }
}

fn setup(
    name: &str,
    call_byte: u8,
) -> (
    ArmedProviderTestDatabase,
    ProviderAuthorityIssueRequest,
    PreparedProviderRecord,
) {
    let database = ArmedProviderTestDatabase::new(name);
    let (request, record) = prepared_request(&database, call_byte);
    (database, request, record)
}

fn prepared_request(
    database: &ArmedProviderTestDatabase,
    call_byte: u8,
) -> (ProviderAuthorityIssueRequest, PreparedProviderRecord) {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([call_byte; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-08-06",
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
    database
        .dispatch()
        .persist_prepared(&database.launch.borrow(), &record)
        .unwrap();
    let request = ProviderAuthorityIssueRequest {
        provider_id: call.model_ref().provider_id().clone(),
        principal_id: "principal-1".into(),
        conversation_id: database.taskrun_receipts[&call_byte].conversation_id,
        taskrun_id: database.taskrun_receipts[&call_byte].taskrun_id,
        execution_attempt_id: database.taskrun_receipts[&call_byte].attempt_id,
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
        provider_idempotency_key: format!("provider-recovery-{call_byte}"),
    };
    (request, record)
}

fn rotated_runtime_config() -> ProviderRuntimeAuthorityConfig {
    let mut config = runtime_config::runtime_config();
    config.generation = 12;
    config.fencing_token = 14;
    config
}

enum Task9FaultPoint {
    BeforeIssueCommit,
}

fn install_fault(
    connection: &rusqlite::Connection,
    point: Task9FaultPoint,
) -> Result<(), rusqlite::Error> {
    match point {
        Task9FaultPoint::BeforeIssueCommit => connection.execute_batch(
            "CREATE TRIGGER abort_provider_issue
             BEFORE INSERT ON provider_execution_admissions
             BEGIN SELECT RAISE(ABORT, 'injected issue rollback'); END;",
        ),
    }
}

fn remove_fault(connection: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    connection.execute_batch("DROP TRIGGER abort_provider_issue;")
}

fn issue_winner(
    database: &ArmedProviderTestDatabase,
    request: &ProviderAuthorityIssueRequest,
) -> ProviderDispatchClaim {
    let ProviderAuthorityIssueOutcome::Winner(admission) = database.issue(request).unwrap() else {
        panic!("first exact issue must win");
    };
    admission.claim().clone()
}

fn credential(
    database: &validated_reopen::ProviderTestDatabase,
) -> (
    SqliteProviderCredentialLifecycleStore,
    CredentialDispatchBinding,
) {
    let store = crate::provider_credential_fixture::credential(
        database,
        "fixture-provider",
        [1; 16],
        13,
        100,
    );
    let binding = store
        .authorize_active(
            &ProviderId::new("fixture-provider").unwrap(),
            [1; 16],
            13,
            100,
        )
        .unwrap();
    (store, binding)
}

fn table_count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn effect_start_count(connection: &Connection) -> i64 {
    table_count(connection, "provider_effect_starts")
}

fn active_reservation_count(connection: &Connection) -> i64 {
    connection
        .query_row(
            "SELECT COUNT(*) FROM provider_budget_reservations WHERE state = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn dispatch_state(
    database: &validated_reopen::ProviderTestDatabase,
    claim: &ProviderDispatchClaim,
) -> ProviderDispatchState {
    database
        .dispatch()
        .get_dispatch(claim.attempt_id)
        .unwrap()
        .unwrap()
        .state
}

fn update_digest_version(
    database: &validated_reopen::ProviderTestDatabase,
    call_id: ProviderCallId,
) {
    let connection = database.connection();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_prepared_requests SET call_digest_version = 3 WHERE call_id = ?1",
            params![call_id.as_bytes().as_slice()],
        )
        .unwrap();
}
