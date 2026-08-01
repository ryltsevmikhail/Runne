use std::sync::{Arc, Barrier};

use gocode_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueOutcome, ProviderAuthorityIssueRequest,
    ProviderExecutionStore, ProviderJournalKeyBinding, RuntimeProviderAuthorityIssuer,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderId,
};
use gocode_store::provider::{
    PreparedProviderRecord, ProviderRuntimeAuthorityConfig, SqliteProviderDispatchStore,
    SqliteProviderExecutionStore,
};
use rusqlite::Connection;

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
        approval_id: "approval-provider-network-1".to_owned(),
        approval_revision: 3,
        approval_allowed: true,
        approval_expires_at: i64::MAX,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
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

fn issue_request(prepared: ContractPreparedProviderRecord) -> ProviderAuthorityIssueRequest {
    ProviderAuthorityIssueRequest {
        principal_id: "principal-1".to_owned(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
        prepared,
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".to_owned(),
        provider_idempotency_key: "provider-execution-1".to_owned(),
    }
}

fn initialize(
    path: &std::path::Path,
) -> (SqliteProviderExecutionStore, ProviderAuthorityIssueRequest) {
    let (prepared, contract, _) = prepared();
    let dispatch = SqliteProviderDispatchStore::open(path).unwrap();
    dispatch.persist_prepared(&prepared).unwrap();
    let execution = SqliteProviderExecutionStore::open(path).unwrap();
    execution.install_runtime_authority(&config()).unwrap();
    (execution, issue_request(contract))
}

#[test]
fn issuance_atomically_commits_claim_reservations_authority_audit_intent_and_permit() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("provider-execution.sqlite");
    let (store, request) = initialize(&path);

    let ProviderAuthorityIssueOutcome::Winner(admitted) = store.issue(&request).unwrap() else {
        panic!("first exact issue must win")
    };

    assert_ne!(admitted.authority_ref().authority_id(), [0; 16]);
    assert_ne!(admitted.claim().attempt_id.as_bytes(), &[0; 16]);
    assert_ne!(admitted.claim().permit_id, [0; 16]);
    assert_ne!(admitted.claim().token_reservation_id, [0; 16]);
    assert_ne!(admitted.claim().cost_reservation_id, [0; 16]);
    assert_eq!(admitted.claim().fencing_token, 13);

    let connection = Connection::open(&path).unwrap();
    for (table, expected) in [
        ("provider_execution_admissions", 1_i64),
        ("provider_dispatch_attempts", 1),
        ("provider_effect_authorities", 1),
        ("provider_budget_reservations", 2),
        ("security_dispatch_intents", 1),
        ("security_authorization_decisions", 1),
        ("security_budget_consumptions", 1),
        ("security_audit_pre_effect", 1),
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
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("provider-retry.sqlite");
    let (store, request) = initialize(&path);

    assert!(matches!(
        store.issue(&request).unwrap(),
        ProviderAuthorityIssueOutcome::Winner(_)
    ));
    assert_eq!(
        store.issue(&request).unwrap(),
        ProviderAuthorityIssueOutcome::Existing {
            state: gocode_provider::ProviderRepositoryState::Dispatching,
        }
    );

    let mut conflict = request;
    conflict.max_cost_micros += 1;
    assert_eq!(
        store.issue(&conflict),
        Err(ProviderAdmissionError::AuthorityConflict)
    );

    let connection = Connection::open(&path).unwrap();
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
            Box::new(|config| config.approval_expires_at = 0),
            ProviderAdmissionError::ApprovalExpired,
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
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary
            .path()
            .join(format!("provider-denial-{index}.sqlite"));
        let (prepared, contract, _) = prepared();
        SqliteProviderDispatchStore::open(&path)
            .unwrap()
            .persist_prepared(&prepared)
            .unwrap();
        let store = SqliteProviderExecutionStore::open(&path).unwrap();
        let mut runtime = config();
        mutate(&mut runtime);
        store.install_runtime_authority(&runtime).unwrap();

        assert_eq!(store.issue(&issue_request(contract)), Err(expected));
        assert_eq!(store.admitted_count().unwrap(), 0);
    }

    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("provider-pricing.sqlite");
    let (store, mut request) = initialize(&path);
    request.pricing_revision_digest = [99; 32];
    assert_eq!(
        store.issue(&request),
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
        store.issue(&request),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    assert_eq!(store.admitted_count().unwrap(), 0);
}

#[test]
fn authority_restart_atomically_freezes_old_live_attempt_before_new_lease_is_usable() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("provider-generation-restart.sqlite");
    let (store, request) = initialize(&path);
    let ProviderAuthorityIssueOutcome::Winner(admitted) = store.issue(&request).unwrap() else {
        panic!("first generation must admit one attempt")
    };
    let attempt_id = admitted.claim().attempt_id;
    SqliteProviderDispatchStore::open(&path)
        .unwrap()
        .mark_streaming(&gocode_store::provider::MarkProviderStreaming {
            attempt_id,
            fencing_token: admitted.claim().fencing_token,
            stream_id: gocode_provider::ProviderStreamId::from_bytes([41; 16]),
        })
        .unwrap();

    let mut restarted = config();
    restarted.generation = 12;
    restarted.fencing_token = 14;
    store
        .install_runtime_authority_and_advance_worker_lease(&restarted)
        .unwrap();

    let reopened = SqliteProviderDispatchStore::open(&path)
        .unwrap()
        .get_dispatch(attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened.state,
        gocode_store::provider::ProviderDispatchState::Uncertain
    );
    assert!(
        SqliteProviderDispatchStore::open(&path)
            .unwrap()
            .mark_streaming(&gocode_store::provider::MarkProviderStreaming {
                attempt_id,
                fencing_token: admitted.claim().fencing_token,
                stream_id: gocode_provider::ProviderStreamId::from_bytes([42; 16]),
            })
            .is_err()
    );
    assert_eq!(
        store.issue(&request),
        Ok(ProviderAuthorityIssueOutcome::Existing {
            state: gocode_provider::ProviderRepositoryState::Uncertain,
        })
    );

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_budget_reservations WHERE released_at IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn begin_immediate_allows_one_winner_across_two_store_handles() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("provider-two-writer.sqlite");
    let (_store, request) = initialize(&path);
    let first = SqliteProviderExecutionStore::open(&path).unwrap();
    let second = SqliteProviderExecutionStore::open(&path).unwrap();
    let barrier = Arc::new(Barrier::new(3));

    let first_barrier = Arc::clone(&barrier);
    let first_request = request.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.issue(&first_request)
    });
    let second_barrier = Arc::clone(&barrier);
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second.issue(&request)
    });
    barrier.wait();

    let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ProviderAuthorityIssueOutcome::Winner(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ProviderAuthorityIssueOutcome::Existing { .. })))
            .count(),
        1
    );
}

#[test]
fn active_journal_key_preflight_returns_only_the_exact_non_secret_binding() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("provider-key-preflight.sqlite");
    let (store, _) = initialize(&path);
    let key = ProviderJournalKeyBinding::new([21; 16], 1, [1; 16], 7).unwrap();

    assert_eq!(store.active_journal_key_binding().unwrap(), None);
    store.activate_journal_key(key).unwrap();
    assert_eq!(store.active_journal_key_binding().unwrap(), Some(key));
}
