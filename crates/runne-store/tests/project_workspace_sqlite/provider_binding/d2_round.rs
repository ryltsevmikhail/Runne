use runne_application::ports::{
    BindPreparedTaskRunProviderRoundEffect, PreparedTaskRunProviderRequest,
    TaskRunAssignmentIdentity, TaskRunProviderBindingPort,
};

pub fn bind_d2_round_zero_for_test(
    database: &crate::project_workspace_sqlite::support::Database,
    identity: &TaskRunAssignmentIdentity,
    conversation_id: runne_domain::id::ConversationId,
    original_claim_version: u64,
    current_taskrun_head: u64,
) {
    use runne_application::provider::ProviderAuthorityIssueRequest;
    use runne_provider::{
        ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
        ProviderCall, ProviderCallId, ProviderId,
    };
    use runne_store::provider::{
        PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
    };
    use std::sync::Arc;

    let config = ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "owner".into(),
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
        profile_digest: [1; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    };
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([0x44; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-31",
        )
        .unwrap(),
        [0x45; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared_call = PreparedRequest::from_call(&call).unwrap();
    let stored = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared_call.request_ref().digest_version(),
        prepared_digest: *prepared_call.request_ref().as_bytes(),
        render_digest: *prepared_call.render_digest(),
        profile_digest: [2; 32],
    };
    let contract = ContractPreparedProviderRecord {
        call_id: stored.call_id,
        call_digest_version: stored.call_digest_version,
        prepared_digest: stored.prepared_digest,
        render_digest: stored.render_digest,
        profile_digest: stored.profile_digest,
    };
    let issue = ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new("fixture-provider").unwrap(),
        principal_id: "owner".into(),
        conversation_id,
        taskrun_id: identity.taskrun_id,
        execution_attempt_id: identity.attempt_id,
        prepared: contract,
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: "taskrun-provider-binding".into(),
    };
    let dispatch =
        crate::validated_reopen::open_provider_dispatch(database.file.path(), database.identity)
            .unwrap();
    let execution =
        crate::validated_reopen::open_provider_execution(database.file.path(), database.identity)
            .unwrap();
    let launch = Arc::new(execution.activate_runtime_launch(&config).unwrap());
    crate::online_proof::arm(&execution, 7);
    dispatch.persist_prepared(&launch, &stored).unwrap();
    let provider_id = ProviderId::new("fixture-provider").unwrap();
    let profile_grant = execution
        .install_secondary_profile_grant(
            &launch,
            runne_application::provider::ProviderSecondaryProfileGrantSpec::new(
                &provider_id,
                "runne-linux-agent-tools-v1",
                "fixture-provider",
                [2; 32],
                [3; 32],
                5_000,
                500_000,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        execution
            .issue_secondary_profile(&launch, &profile_grant, &issue)
            .unwrap(),
        ProviderAuthorityIssueOutcome::Winner(_)
    ));
    database
        .store
        .bind_prepared_taskrun_provider_round_effect(BindPreparedTaskRunProviderRoundEffect {
            identity: identity.clone(),
            original_claim_version,
            current_taskrun_head,
            round_index: 0,
            previous_tool_result: None,
            prepared: PreparedTaskRunProviderRequest {
                call_id: stored.call_id,
                call_digest_version: stored.call_digest_version,
                prepared_digest: stored.prepared_digest,
                render_digest: stored.render_digest,
                profile_digest: stored.profile_digest,
                provider_idempotency_key: issue.provider_idempotency_key,
            },
        })
        .unwrap();
}

#[test]
fn d2_round_pre_effect_verification_matches_complete_binding() {
    use runne_application::ports::{
        BindPreparedTaskRunProviderRoundEffect, EventStore, TaskRunProviderBindingPort,
        TaskRunProviderBindingResult, TaskRunProviderToolResultRef,
    };
    use runne_domain::id::{AttemptId, CycleId};
    use runne_provider::ProviderCallDigestVersion;

    let fixture = super::fixture("d2-round-complete-verification");
    let taskrun_id = fixture.identity.taskrun_id;
    let stream = fixture.database.store.load_task_run(taskrun_id).unwrap();
    let connection = fixture.database.connection();
    let claim_version: i64 = connection
        .query_row(
            "SELECT new_version FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3",
            rusqlite::params![taskrun_id.as_bytes(), fixture.identity.fence.0 as i64, fixture.identity.attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    fixture
        .database
        .store
        .ensure_taskrun_tool_loop_budget(taskrun_id, stream.current_version, &fixture.identity, 1)
        .unwrap();
    let request = BindPreparedTaskRunProviderRoundEffect {
        identity: fixture.identity.clone(),
        original_claim_version: u64::try_from(claim_version).unwrap(),
        current_taskrun_head: stream.current_version,
        round_index: 0,
        previous_tool_result: None,
        prepared: fixture.prepared.clone(),
    };
    assert_eq!(
        fixture
            .database
            .store
            .bind_prepared_taskrun_provider_round_effect(request.clone()),
        Ok(TaskRunProviderBindingResult::Bound)
    );
    fixture
        .database
        .store
        .verify_prepared_taskrun_provider_round_effect(request.clone())
        .unwrap();

    let mut mismatches = Vec::new();
    let mut changed = request.clone();
    changed.original_claim_version += 1;
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.current_taskrun_head += 1;
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.identity.node_epoch += 1;
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.identity.node_id.0.push_str("-changed");
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.identity.attempt_id = AttemptId::from_bytes([0x55; 16]);
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.prepared.call_id = runne_provider::ProviderCallId::from_bytes([0x54; 16]);
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.prepared.call_digest_version = ProviderCallDigestVersion::V1;
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.prepared.prepared_digest[0] ^= 1;
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.prepared.render_digest[0] ^= 1;
    mismatches.push(changed);
    let mut changed = request.clone();
    changed.prepared.profile_digest[0] ^= 1;
    mismatches.push(changed);
    let mut changed = request.clone();
    changed
        .prepared
        .provider_idempotency_key
        .push_str("-changed");
    mismatches.push(changed);
    let mut changed = request;
    changed.previous_tool_result = Some(TaskRunProviderToolResultRef {
        attempt_id: AttemptId::from_bytes([0x56; 16]),
        cycle_id: CycleId::from_bytes([0x57; 16]),
        proposal_index: 0,
        semantic_digest: runne_domain::id::IntegrityDigest::from_bytes([0x58; 32]),
        result_digest: runne_domain::id::IntegrityDigest::from_bytes([0x59; 32]),
    });
    changed.round_index = 1;
    mismatches.push(changed);
    for mismatch in mismatches {
        assert!(
            fixture
                .database
                .store
                .verify_prepared_taskrun_provider_round_effect(mismatch)
                .is_err()
        );
    }
}
