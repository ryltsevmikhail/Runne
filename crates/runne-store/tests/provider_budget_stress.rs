#![allow(dead_code)]

use runne_application::provider::{ProviderAdmissionError, ProviderAuthorityIssueRequest};
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderId,
};
use runne_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};

#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/provider_taskrun_start.rs"]
mod provider_taskrun_start;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

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
        activation_binding_kind: runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 1_000_000,
        cost_budget_limit_micros: 10_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

fn request(
    index: u8,
    dispatch: &SqliteProviderDispatchStore,
    launch: &runne_store::provider::ProviderRuntimeLaunchCapability,
    started: &runne_application::ports::TextGenerationReceipt,
) -> ProviderAuthorityIssueRequest {
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
    dispatch.persist_prepared(launch, &record).unwrap();
    ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new("fixture").unwrap(),
        principal_id: "principal".into(),
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
        requested_input_tokens: 1,
        requested_output_tokens: u64::from(TOKENS_PER_ATTEMPT - 1),
        max_cost_micros: COST_PER_ATTEMPT,
        currency: "USD".into(),
        provider_idempotency_key: format!("budget-stress-{index}"),
    }
}

#[test]
fn cumulative_limits_are_exact_across_many_admissions_and_reopen() {
    let database = validated_reopen::ProviderTestDatabase::new("budget-stress");
    let started_receipts = provider_taskrun_start::begin_many(
        database.path(),
        [1; 16],
        "principal",
        "provider budget fixture",
        &(1..=ATTEMPTS + 1).collect::<Vec<_>>(),
    );
    let dispatch = database.dispatch();
    assert!(SqliteProviderExecutionStore::open(database.as_path()).is_err());
    let execution = database.execution();
    let launch = execution.activate_runtime_launch(&authority()).unwrap();
    online_proof::arm(&execution, 7);

    for index in 1..=ATTEMPTS {
        assert!(matches!(
            execution.issue(
                &launch,
                &request(
                    index,
                    &dispatch,
                    &launch,
                    &started_receipts[usize::from(index - 1)]
                )
            ),
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

    let reopened = database.execution();
    assert_eq!(reopened.utilization().unwrap(), (tokens, cost));
    let reopened_launch = reopened.activate_runtime_launch(&authority()).unwrap();
    online_proof::arm(&reopened, 7);
    assert_eq!(reopened.utilization().unwrap(), (tokens, cost));
    assert_eq!(
        reopened.issue(
            &reopened_launch,
            &request(
                11,
                &dispatch,
                &reopened_launch,
                &started_receipts[ATTEMPTS as usize]
            ),
        ),
        Err(ProviderAdmissionError::TokenBudgetDenied)
    );
}
