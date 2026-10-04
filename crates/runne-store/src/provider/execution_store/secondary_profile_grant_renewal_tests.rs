use runne_application::provider::{
    ProviderAuthorityIssueRequest, ProviderExecutionStore, ProviderJournalAppendRequest,
    ProviderJournalKeyBinding, ProviderSecondaryProfileGrantSpec,
};
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallDigestVersion, ProviderCallId, ProviderId,
};

use super::authority_test_support::{configured_connection, prepare_request_for_provider};
use super::secondary_profile_grant_tests as helpers;
use super::{ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore};

#[test]
fn owner_revision_renewal_rebinds_without_resetting_budget_or_old_terminal_history() {
    let (fixture, lifecycle) = helpers::secondary_online_fixture();
    let old = helpers::grant(&fixture, "openai");
    let old_admission = helpers::winner(helpers::issue(&fixture, &old, "openai", 81));
    helpers::start_online_stream(&fixture, &lifecycle, &old_admission);
    helpers::append_terminal(&fixture, &old_admission);
    let spent_before_renewal = fixture
        .store
        .secondary_profile_utilization(fixture.launch(), &old)
        .unwrap();

    let mut renewed_config = fixture.config.clone();
    renewed_config.capability_revision += 1;
    renewed_config.approval_revision += 1;
    let renewed_launch = fixture.activate(&renewed_config);
    let renewed = fixture
        .store
        .install_secondary_profile_grant(&renewed_launch, old.spec().clone())
        .unwrap();
    assert!(
        fixture
            .store
            .secondary_profile_utilization(&renewed_launch, &old)
            .is_err(),
        "the superseded binding capability must be stale"
    );
    assert!(matches!(
        fixture.store.issue_secondary_profile(
            &renewed_launch,
            &old,
            &prepare_request_for_provider(&renewed_launch, &fixture.path, 82, "openai"),
        ),
        Err(runne_application::provider::ProviderAdmissionError::StaleFencingToken)
            | Err(runne_application::provider::ProviderAdmissionError::AuthorityDenied)
    ));
    let claim = old_admission.claim();
    assert!(
        fixture
            .store
            .begin_provider_poll(&runne_application::provider::ProviderPollRequest {
                attempt_id: claim.attempt_id,
                fencing_token: claim.fencing_token,
                cursor: 1,
                profile_digest: [2; 32],
                runtime_generation: 11,
            })
            .is_err(),
        "old binding cannot poll after renewal"
    );
    assert!(
        fixture
            .store
            .append_encrypted_event(&ProviderJournalAppendRequest {
                attempt_id: claim.attempt_id,
                fencing_token: claim.fencing_token,
                sequence: 1,
                event_kind: 1,
                terminal: false,
                call_digest_version: ProviderCallDigestVersion::V2,
                profile_digest: [2; 32],
                runtime_generation: 11,
                key: ProviderJournalKeyBinding::new([9; 16], 1, [1; 16], 7).unwrap(),
                encrypted: helpers::encrypted(85, 86),
            })
            .is_err(),
        "old binding cannot append after renewal"
    );
    assert_eq!(
        fixture
            .store
            .secondary_profile_utilization(&renewed_launch, &renewed)
            .unwrap(),
        spent_before_renewal,
        "renewal keeps the same independent budget ledger"
    );
    for (profile, pricing, token_limit, cost_limit) in [
        ([2; 32], [3; 32], 6_000, 500_000),
        ([8; 32], [3; 32], 5_000, 500_000),
        ([2; 32], [9; 32], 5_000, 500_000),
    ] {
        let altered = ProviderSecondaryProfileGrantSpec::new(
            &ProviderId::new("openai").unwrap(),
            "background-text-v1",
            "openai",
            profile,
            pricing,
            token_limit,
            cost_limit,
        )
        .unwrap();
        assert!(
            fixture
                .store
                .install_secondary_profile_grant(&renewed_launch, altered)
                .is_err()
        );
    }

    assert_eq!(
        helpers::runtime_settlement::finalize(&fixture, &old_admission),
        runne_application::provider::ProviderTerminalCommitOutcome::Committed
    );
    assert_eq!(
        helpers::runtime_settlement::finalize(&fixture, &old_admission),
        runne_application::provider::ProviderTerminalCommitOutcome::Replayed
    );
    let reopened = SqliteProviderExecutionStore::open_with_connection(
        fixture.path.to_str().unwrap(),
        configured_connection(&fixture.path),
    )
    .unwrap();
    let (tokens, costs) = reopened
        .secondary_profile_utilization(&renewed_launch, &renewed)
        .unwrap();
    assert_eq!((tokens.reserved, tokens.settled), (0, 1_400));
    assert_eq!((costs.reserved, costs.settled), (0, 40_000));
}

#[test]
fn revoked_ledger_cannot_be_reenabled_by_owner_renewal() {
    let fixture = helpers::secondary_fixture();
    let old = helpers::grant(&fixture, "fixture-provider");
    fixture
        .store
        .revoke_secondary_profile_grant(fixture.launch(), &old)
        .unwrap();
    let mut renewed_config = fixture.config.clone();
    renewed_config.capability_revision += 1;
    renewed_config.approval_revision += 1;
    let reopened = SqliteProviderExecutionStore::open_with_connection(
        fixture.path.to_str().unwrap(),
        configured_connection(&fixture.path),
    )
    .unwrap();
    let renewed_launch = reopened.activate_runtime_launch(&renewed_config).unwrap();
    assert!(
        reopened
            .install_secondary_profile_grant(&renewed_launch, old.spec().clone())
            .is_err()
    );
    assert!(
        reopened
            .install_secondary_profile_grant_if_active(&renewed_launch, old.spec().clone())
            .unwrap()
            .is_none()
    );
    let provider = runne_provider::ProviderId::new(old.spec().provider_id()).unwrap();
    let changed = ProviderSecondaryProfileGrantSpec::new(
        &provider,
        old.spec().profile_id(),
        old.spec().credential_realm(),
        old.spec().profile_digest(),
        old.spec().pricing_revision_digest(),
        old.spec().token_budget_limit(),
        old.spec().cost_budget_limit_micros() + 1,
    )
    .unwrap();
    assert!(
        reopened
            .install_secondary_profile_grant_if_active(&renewed_launch, changed)
            .is_err()
    );
}

#[test]
fn concurrent_primary_and_secondary_admissions_reserve_separate_ledgers() {
    let fixture = super::authority_test_support::Fixture::new(100);
    fixture.install();
    let provider = ProviderId::new("fixture-provider").unwrap();
    let secondary_profile = [22; 32];
    let grant = fixture
        .store
        .install_secondary_profile_grant(
            fixture.launch(),
            ProviderSecondaryProfileGrantSpec::new(
                &provider,
                "background-text-v1",
                "fixture-provider",
                secondary_profile,
                [3; 32],
                2_000,
                100_000,
            )
            .unwrap(),
        )
        .unwrap();
    let primary_before = fixture.store.utilization().unwrap();
    let secondary_request =
        prepare_profiled_request(fixture.launch(), &fixture.path, 83, secondary_profile);
    let mut primary_request =
        prepare_request_for_provider(fixture.launch(), &fixture.path, 84, "fixture-provider");
    (
        primary_request.conversation_id,
        primary_request.taskrun_id,
        primary_request.execution_attempt_id,
    ) = super::canonical_started_test_support::seed_distinct(&fixture.path, 84);
    let (secondary_result, primary_result) = std::thread::scope(|scope| {
        let secondary = scope.spawn(|| {
            fixture
                .store
                .issue_secondary_profile(fixture.launch(), &grant, &secondary_request)
        });
        let primary = scope.spawn(|| fixture.store.issue(fixture.launch(), &primary_request));
        (secondary.join().unwrap(), primary.join().unwrap())
    });
    assert!(matches!(
        &secondary_result,
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
    assert!(
        matches!(
            &primary_result,
            Ok(ProviderAuthorityIssueOutcome::Winner(_))
        ),
        "primary result: {primary_result:?}; secondary result: {secondary_result:?}"
    );
    assert_eq!(
        fixture.store.utilization().unwrap().0.reserved,
        primary_before.0.reserved + 1_536
    );
    let (tokens, costs) = fixture
        .store
        .secondary_profile_utilization(fixture.launch(), &grant)
        .unwrap();
    assert_eq!((tokens.reserved, costs.reserved), (1_536, 50_000));
}

fn prepare_profiled_request(
    launch: &crate::provider::ProviderRuntimeLaunchCapability,
    path: &std::path::Path,
    discriminator: u8,
    profile_digest: [u8; 32],
) -> ProviderAuthorityIssueRequest {
    let (conversation_id, taskrun_id, execution_attempt_id) =
        super::canonical_started_test_support::seed_distinct(path, discriminator);
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
    let record = crate::provider::PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest,
    };
    crate::provider::SqliteProviderDispatchStore::open_with_connection(
        path.to_str().unwrap(),
        configured_connection(path),
    )
    .unwrap()
    .persist_prepared(launch, &record)
    .unwrap();
    ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new("fixture-provider").unwrap(),
        principal_id: "principal-1".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id,
        prepared: ContractPreparedProviderRecord {
            call_id: record.call_id,
            call_digest_version: record.call_digest_version,
            prepared_digest: record.prepared_digest,
            render_digest: record.render_digest,
            profile_digest,
        },
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: format!("secondary-concurrent-{discriminator}"),
    }
}
