use std::path::PathBuf;

use runne_application::provider::{ProviderAdmissionError, ProviderAuthorityIssueRequest};
use runne_provider::{
    ModelRef, PreparedProviderRecord, PreparedRequest, ProviderCall, ProviderCallId, ProviderId,
};
use runne_store::provider::{
    ProviderRuntimeAuthorityConfig, ProviderRuntimeLaunchCapability, SqliteProviderExecutionStore,
};
use rusqlite::Connection;

#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/provider_taskrun_start.rs"]
mod provider_taskrun_start;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

fn fixture() -> (
    validated_reopen::ProviderTestDatabase,
    PathBuf,
    SqliteProviderExecutionStore,
    ProviderAuthorityIssueRequest,
    ProviderRuntimeLaunchCapability,
) {
    let database = validated_reopen::ProviderTestDatabase::new("provider-post-commit-readback");
    let started = provider_taskrun_start::begin(
        database.path(),
        [1; 16],
        "principal-1",
        "provider post-commit fixture",
    );
    let receipt = started.receipt.clone();
    drop(started);
    let path = database.as_path().to_path_buf();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "model",
            "2026-08-01",
        )
        .unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let prepared_record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [2; 32],
    };
    let store = database.execution();
    let launch = store
        .activate_runtime_launch(&ProviderRuntimeAuthorityConfig {
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
            activation_binding_kind:
                runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    database
        .dispatch()
        .persist_prepared(
            &launch,
            &runne_store::provider::PreparedProviderRecord {
                call_id: prepared_record.call_id,
                call_digest_version: prepared_record.call_digest_version,
                prepared_digest: prepared_record.prepared_digest,
                render_digest: prepared_record.render_digest,
                profile_digest: prepared_record.profile_digest,
            },
        )
        .unwrap();
    online_proof::arm(&store, 7);
    let request = ProviderAuthorityIssueRequest {
        provider_id: call.model_ref().provider_id().clone(),
        principal_id: "principal-1".into(),
        conversation_id: receipt.conversation_id,
        taskrun_id: receipt.taskrun_id,
        execution_attempt_id: receipt.attempt_id,
        prepared: prepared_record,
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: "provider-execution-1".into(),
    };
    (database, path, store, request, launch)
}

fn install_mutating_trigger(path: &PathBuf, assignment: &str) {
    Connection::open(path)
        .unwrap()
        .execute_batch(&format!(
            "CREATE TRIGGER provider_execution_readback_failure
             AFTER INSERT ON provider_execution_admissions
             BEGIN
                 UPDATE provider_execution_admissions SET {assignment}
                  WHERE provider_idempotency_key = NEW.provider_idempotency_key;
             END"
        ))
        .unwrap();
}

fn assert_post_claim_uncertain(assignment: &str) {
    let (_database, path, store, request, launch) = fixture();
    install_mutating_trigger(&path, assignment);
    assert_eq!(
        store.issue(&launch, &request),
        Err(ProviderAdmissionError::PostClaimUncertain)
    );
    assert_eq!(store.admitted_count().unwrap(), 1);
}

#[test]
fn post_commit_readback_failure_is_uncertain_and_preserves_the_durable_claim() {
    assert_post_claim_uncertain("principal_id = 'post-commit-readback-mismatch'");
}

#[test]
fn post_commit_readback_rejects_mutated_revocation_disposition_markers() {
    assert_post_claim_uncertain("capability_revocation_observed = 1");
    assert_post_claim_uncertain("approval_revocation_observed = 1");
}
