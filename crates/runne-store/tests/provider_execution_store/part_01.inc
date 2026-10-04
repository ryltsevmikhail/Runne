use runne_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderExecutionStore,
    ProviderJournalKeyBinding,
};
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderId,
};
use runne_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
    ProviderRuntimeLaunchCapability, SqliteProviderExecutionStore,
};
use std::sync::{Arc, Barrier};
type AuthorityMutation = (
    Box<dyn Fn(&mut ProviderRuntimeAuthorityConfig)>,
    ProviderAdmissionError,
);
fn config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".to_owned(),
        owner_id: "runtime-owner-1".to_owned(),
        scope: "provider.dispatch".to_owned(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "grant-provider-network-1".to_owned(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-provider-network-1".to_owned(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}
fn prepared() -> (
    PreparedProviderRecord,
    ContractPreparedProviderRecord,
    ProviderCall,
) {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-31",
        )
        .unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let store_record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [2; 32],
    };
    let contract_record = ContractPreparedProviderRecord {
        call_id: store_record.call_id,
        call_digest_version: store_record.call_digest_version,
        prepared_digest: store_record.prepared_digest,
        render_digest: store_record.render_digest,
        profile_digest: store_record.profile_digest,
    };
    (store_record, contract_record, call)
}
fn issue_request(
    prepared: ContractPreparedProviderRecord,
    started: &runne_application::ports::TextGenerationReceipt,
) -> ProviderAuthorityIssueRequest {
    ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new("fixture-provider").unwrap(),
        principal_id: "principal-1".to_owned(),
        conversation_id: started.conversation_id,
        taskrun_id: started.taskrun_id,
        execution_attempt_id: started.attempt_id,
        prepared,
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".to_owned(),
        provider_idempotency_key: "provider-execution-1".to_owned(),
    }
}
fn arm(store: &SqliteProviderExecutionStore) {
    crate::online_proof::arm(store, 7);
}
fn initialize(
    database: &validated_reopen::ProviderTestDatabase,
) -> (
    SqliteProviderExecutionStore,
    Arc<ProviderRuntimeLaunchCapability>,
    ProviderAuthorityIssueRequest,
) {
    let (prepared, contract, _) = prepared();
    let started = provider_taskrun_start::begin(
        database.path(),
        [1; 16],
        "principal-1",
        "provider execution store fixture",
    );
    let receipt = started.receipt.clone();
    drop(started);
    let execution = database.execution();
    let launch = Arc::new(execution.activate_runtime_launch(&config()).unwrap());
    arm(&execution);
    database
        .dispatch()
        .persist_prepared(&launch, &prepared)
        .unwrap();
    (execution, launch, issue_request(contract, &receipt))
}
#[test]
fn issuance_atomically_commits_claim_reservations_authority_audit_intent_and_permit() {
    let database = validated_reopen::ProviderTestDatabase::new("provider-execution");
    let (store, launch, request) = initialize(&database);
    let ProviderAuthorityIssueOutcome::Winner(admitted) = store.issue(&launch, &request).unwrap()
    else {
        panic!("first exact issue must win")
    };
    let (tokens, cost) = store.utilization().unwrap();
    assert_eq!(
        (
            tokens.limit,
            tokens.reserved,
            tokens.settled,
            tokens.remaining
        ),
        (10_000, 1_536, 0, 8_464)
    );
    assert_eq!(
        (cost.limit, cost.reserved, cost.settled, cost.remaining),
        (1_000_000, 50_000, 0, 950_000)
    );
    assert_ne!(admitted.authority_ref().authority_id(), [0; 16]);
    assert_ne!(admitted.claim().attempt_id.as_bytes(), &[0; 16]);
    assert_ne!(admitted.claim().permit_id, [0; 16]);
    assert_ne!(admitted.claim().token_reservation_id, [0; 16]);
    assert_ne!(admitted.claim().cost_reservation_id, [0; 16]);
    assert_eq!(admitted.claim().fencing_token, 13);
    let connection = database.connection();
    for (table, expected) in [
        ("provider_execution_admissions", 1_i64),
        ("provider_dispatch_attempts", 1),
        ("provider_effect_authorities", 1),
        ("provider_budget_reservations", 2),
        ("security_dispatch_intents", 1),
        ("security_authorization_decisions", 1),
        ("security_budget_consumptions", 1),
        ("security_audit_pre_effect", 0),
        ("security_permit_claims", 1),
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected, "unexpected atomic row count for {table}");
    }
}
#[test]
fn exact_retry_replays_without_new_ids_or_budget_and_changed_semantics_conflict() {
    let database = validated_reopen::ProviderTestDatabase::new("provider-retry");
    let (store, launch, request) = initialize(&database);

    assert!(matches!(
        store.issue(&launch, &request).unwrap(),
        ProviderAuthorityIssueOutcome::Winner(_)
    ));
    assert_eq!(
        store.issue(&launch, &request).unwrap(),
        ProviderAuthorityIssueOutcome::Existing {
            state: runne_provider::ProviderRepositoryState::Dispatching,
        }
    );

    let mut conflict = request;
    conflict.max_cost_micros += 1;
    assert_eq!(
        store.issue(&launch, &conflict),
        Err(ProviderAdmissionError::AuthorityConflict)
    );

    let connection = database.connection();
    let reservation_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_budget_reservations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reservation_count, 2);
}

#[test]
fn policy_approval_budget_pricing_and_generation_denials_leave_no_claim() {
    let mutations: Vec<AuthorityMutation> = vec![
        (
            Box::new(|config| config.capability_allowed = false),
            ProviderAdmissionError::CapabilityDenied,
        ),
        (
            Box::new(|config| config.approval_allowed = false),
            ProviderAdmissionError::ApprovalDenied,
        ),
        (
            Box::new(|config| config.approval_allowed = false),
            ProviderAdmissionError::ApprovalDenied,
        ),
        (
            Box::new(|config| config.token_budget_limit = 1),
            ProviderAdmissionError::TokenBudgetDenied,
        ),
        (
            Box::new(|config| config.cost_budget_limit_micros = 1),
            ProviderAdmissionError::CostBudgetDenied,
        ),
    ];

    for (index, (mutate, expected)) in mutations.into_iter().enumerate() {
        let database =
            validated_reopen::ProviderTestDatabase::new(&format!("provider-denial-{index}"));
        let (prepared, contract, _) = prepared();
        let started = provider_taskrun_start::begin(
            database.path(),
            [1; 16],
            "principal-1",
            "provider execution denial fixture",
        );
        let receipt = started.receipt.clone();
        drop(started);
        let store = database.execution();
        let mut runtime = config();
        mutate(&mut runtime);
        let launch = store.activate_runtime_launch(&runtime).unwrap();
        arm(&store);
        database
            .dispatch()
            .persist_prepared(&launch, &prepared)
            .unwrap();

        assert_eq!(
            store.issue(&launch, &issue_request(contract, &receipt)),
            Err(expected)
        );
        assert_eq!(store.admitted_count().unwrap(), 0);
    }

    let database = validated_reopen::ProviderTestDatabase::new("provider-pricing");
    let (store, launch, mut request) = initialize(&database);
    request.pricing_revision_digest = [99; 32];
    assert_eq!(
        store.issue(&launch, &request),
        Err(ProviderAdmissionError::PricingRevisionMismatch)
    );
    assert_eq!(store.admitted_count().unwrap(), 0);

    store.advance_worker_lease(12, 14).unwrap();
    assert_eq!(
        store.advance_worker_lease(11, 13),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    assert_eq!(
        store.advance_worker_lease(12, 15),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    store.advance_worker_lease(12, 14).unwrap();
    request.pricing_revision_digest = [3; 32];
    assert_eq!(
        store.issue(&launch, &request),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    assert_eq!(store.admitted_count().unwrap(), 0);
}
