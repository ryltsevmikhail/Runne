use gocode_application::provider::{ProviderAdmissionError, ProviderAuthorityIssueRequest};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderDispatchClaim, ProviderId,
};
use gocode_store::provider::{
    CredentialDispatchBinding, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderDispatchState, ProviderRuntimeAuthorityConfig,
    SqliteProviderCredentialLifecycleStore,
};
use rusqlite::{Connection, params};

fn setup(
    name: &str,
    call_byte: u8,
) -> (
    validated_reopen::ProviderTestDatabase,
    ProviderAuthorityIssueRequest,
    PreparedProviderRecord,
) {
    let database = validated_reopen::ProviderTestDatabase::new(name);
    let (request, record) = prepared_request(&database, call_byte);
    database
        .execution()
        .install_runtime_authority(&runtime_config())
        .unwrap();
    (database, request, record)
}

fn prepared_request(
    database: &validated_reopen::ProviderTestDatabase,
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
    database.dispatch().persist_prepared(&record).unwrap();
    let request = ProviderAuthorityIssueRequest {
        principal_id: "principal-1".into(),
        conversation_id: ConversationId::from_bytes([call_byte.wrapping_add(10); 16]),
        taskrun_id: TaskRunId::from_bytes([call_byte.wrapping_add(20); 16]),
        execution_attempt_id: AttemptId::from_bytes([call_byte.wrapping_add(30); 16]),
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

fn runtime_config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".into(),
        owner_id: "runtime-owner-1".into(),
        scope: "provider.dispatch".into(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "grant-provider-network-1".into(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-provider-network-1".into(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: gocode_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

fn rotated_runtime_config() -> ProviderRuntimeAuthorityConfig {
    let mut config = runtime_config();
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
    database: &validated_reopen::ProviderTestDatabase,
    request: &ProviderAuthorityIssueRequest,
) -> ProviderDispatchClaim {
    let ProviderAuthorityIssueOutcome::Winner(admission) = database.execution().issue(request).unwrap()
    else {
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
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
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

fn update_digest_version(database: &validated_reopen::ProviderTestDatabase, call_id: ProviderCallId) {
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

#[derive(Debug, PartialEq, Eq)]
struct SqlSnapshot(Vec<(String, Vec<Vec<String>>)>);

fn sql_snapshot(connection: &Connection) -> SqlSnapshot {
    let mut tables = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap();
    let tables = tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    SqlSnapshot(
        tables
            .into_iter()
            .map(|table| (table.clone(), sql_table_rows(connection, &table)))
            .collect(),
    )
}

fn sql_table_rows(connection: &Connection, table: &str) -> Vec<Vec<String>> {
    let columns = connection
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let values = columns
        .iter()
        .map(|column| format!("quote(\"{column}\")"))
        .collect::<Vec<_>>()
        .join(", ");
    let order = (1..=columns.len())
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut rows = connection
        .prepare(&format!("SELECT {values} FROM \"{table}\" ORDER BY {order}"))
        .unwrap();
    rows.query_map([], |row| {
        (0..columns.len())
            .map(|index| row.get::<_, String>(index))
            .collect()
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
}
