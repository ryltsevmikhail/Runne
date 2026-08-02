use gocode_application::provider::{ProviderAdmissionError, ProviderAuthorityIssueRequest};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderId,
};
use gocode_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};

const ATTEMPTS: u8 = 10;
const TOKENS_PER_ATTEMPT: u32 = 100_000;
const COST_PER_ATTEMPT: u64 = 1_000_000;

fn authority() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal".into(),
        owner_id: "owner".into(),
        scope: "provider.dispatch".into(),
        generation: 1,
        fencing_token: 1,
        capability_grant_id: "grant".into(),
        capability_revision: 1,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval".into(),
        approval_revision: 1,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind:
            gocode_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 1_000_000,
        cost_budget_limit_micros: 10_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

fn request(index: u8, dispatch: &SqliteProviderDispatchStore) -> ProviderAuthorityIssueRequest {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([index; 16]),
        ModelRef::new(ProviderId::new("fixture").unwrap(), "model", "2026-08-01").unwrap(),
        [index; 32],
        TOKENS_PER_ATTEMPT - 1,
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
    dispatch.persist_prepared(&record).unwrap();
    ProviderAuthorityIssueRequest {
        principal_id: "principal".into(),
        conversation_id: ConversationId::from_bytes([index; 16]),
        taskrun_id: TaskRunId::from_bytes([index; 16]),
        execution_attempt_id: AttemptId::from_bytes([index; 16]),
        prepared: ContractPreparedProviderRecord {
            call_id: record.call_id,
            call_digest_version: record.call_digest_version,
            prepared_digest: record.prepared_digest,
            render_digest: record.render_digest,
            profile_digest: record.profile_digest,
        },
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 1,
        requested_output_tokens: u64::from(TOKENS_PER_ATTEMPT - 1),
        max_cost_micros: COST_PER_ATTEMPT,
        currency: "USD".into(),
        provider_idempotency_key: format!("budget-stress-{index}"),
    }
}

#[test]
fn cumulative_limits_are_exact_across_many_admissions_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("budget-stress.sqlite");
    let dispatch = SqliteProviderDispatchStore::open(&path).unwrap();
    let execution = SqliteProviderExecutionStore::open(&path).unwrap();
    execution.install_runtime_authority(&authority()).unwrap();

    for index in 1..=ATTEMPTS {
        assert!(matches!(
            execution.issue(&request(index, &dispatch)),
            Ok(ProviderAuthorityIssueOutcome::Winner(_))
        ));
    }
    let (tokens, cost) = execution.utilization().unwrap();
    assert_eq!(
        (
            tokens.limit,
            tokens.reserved,
            tokens.settled,
            tokens.remaining
        ),
        (1_000_000, 1_000_000, 0, 0)
    );
    assert_eq!(
        (cost.limit, cost.reserved, cost.settled, cost.remaining),
        (10_000_000, 10_000_000, 0, 0)
    );

    let reopened = SqliteProviderExecutionStore::open(&path).unwrap();
    assert_eq!(reopened.utilization().unwrap(), (tokens, cost));
    reopened.install_runtime_authority(&authority()).unwrap();
    assert_eq!(reopened.utilization().unwrap(), (tokens, cost));
    assert_eq!(
        reopened.issue(&request(11, &dispatch)),
        Err(ProviderAdmissionError::TokenBudgetDenied)
    );
}
