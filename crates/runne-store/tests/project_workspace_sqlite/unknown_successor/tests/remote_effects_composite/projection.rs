use super::support::{commit, commit_with, prepare, read};
use runne_application::provider::{
    ProviderRemoteAccountingProjection, ProviderRemoteLocalDisposition,
};
use runne_provider::{ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError};
use runne_provider::{ProviderRemoteResponseStatus, ProviderUsage};
use runne_runtime::provider_execution::ProviderRemoteTerminalSourceOutcome;

struct UnavailablePrice;

impl ProviderTerminalPricing for UnavailablePrice {
    fn price_terminal_usage(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: i64,
        _: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        Err(ProviderTerminalPricingError::Unavailable)
    }
}

#[test]
fn authenticated_completed_source_projects_known_usage_and_price_from_sqlite() {
    let prepared = prepare(
        "remote-effects-known-finance",
        0xd1,
        "resp_effects_known_finance",
        ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        },
        Some("private output remains outside effects"),
    );
    assert_eq!(
        commit(&prepared),
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );

    let snapshot = read(&prepared);
    let remote = snapshot.remote.expect("validated SQLite source snapshot");
    assert_eq!(remote.binding.taskrun_id, prepared.fixture.taskrun_id);
    assert_eq!(remote.binding.dispatch_attempt_id, prepared.attempt);
    assert_eq!(
        remote.fact.as_ref().unwrap().status(),
        &ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        }
    );
    assert_eq!(
        remote.local_disposition,
        ProviderRemoteLocalDisposition::Pending
    );
    assert_eq!(
        remote.accounting,
        ProviderRemoteAccountingProjection::Known {
            input_tokens: 3,
            output_tokens: 4,
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
            charge_micros: 10,
            currency: "USD".into(),
        }
    );
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Known
    );
    assert_eq!(snapshot.effects.remote.usage_known, Some(true));
    assert!(remote.fact.unwrap().output_digest().is_some());
}

#[test]
fn missing_usage_keeps_finance_unknown_even_when_pricing_is_available() {
    let prepared = prepare(
        "remote-effects-missing-usage",
        0xd2,
        "resp_effects_missing_usage",
        ProviderRemoteResponseStatus::Failed {
            code: Some("provider_failed".into()),
            usage: None,
        },
        None,
    );
    assert_eq!(
        commit(&prepared),
        ProviderRemoteTerminalSourceOutcome::AuditOnly
    );
    let snapshot = read(&prepared);
    let remote = snapshot.remote.unwrap();
    assert_eq!(
        remote.accounting,
        ProviderRemoteAccountingProjection::Unknown
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Unknown
    );
    assert_eq!(snapshot.effects.remote.usage_known, Some(false));

    let reserve_count: i64 = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM provider_budget_reservations b
             JOIN provider_dispatch_attempts p ON p.provider_idempotency_key=b.provider_idempotency_key
             WHERE p.attempt_id=?1 AND b.state=1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        reserve_count, 2,
        "unknown accounting preserves both reserves"
    );
}

#[test]
fn present_usage_with_unpriceable_settlement_is_not_misreported_as_missing_usage() {
    let prepared = prepare(
        "remote-effects-usage-unpriceable",
        0xd3,
        "resp_effects_usage_unpriceable",
        ProviderRemoteResponseStatus::Failed {
            code: Some("provider_failed".into()),
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        },
        None,
    );
    assert_eq!(
        commit_with(&prepared, &UnavailablePrice),
        ProviderRemoteTerminalSourceOutcome::AuditOnly
    );
    let snapshot = read(&prepared);
    assert_eq!(snapshot.effects.remote.usage_known, Some(true));
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Unknown
    );
    let reserve_count: i64 = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM provider_budget_reservations b
             JOIN provider_dispatch_attempts p ON p.provider_idempotency_key=b.provider_idempotency_key
             WHERE p.attempt_id=?1 AND b.state=1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        reserve_count, 2,
        "unpriceable settlement preserves both reserves"
    );
}

#[test]
fn runtime_owned_primary_text_claim_authenticates_complete_source_and_projection() {
    let fixture = super::super::super::fixture::runtime_text(
        "runtime-primary-text-source",
        0x31,
        "resp_runtime_primary",
    );
    let prepared = super::support::prepare_fixture(
        fixture,
        "resp_runtime_primary",
        ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        },
        Some("synthetic retained text"),
    );
    assert_eq!(
        commit(&prepared),
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );
    let snapshot = read(&prepared);
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Known
    );
}

#[test]
fn runtime_owned_primary_text_claim_rejects_wrong_actor_and_tool_budget() {
    for wrong_actor in [true, false] {
        let fixture = super::super::super::fixture::runtime_text_with_actor(
            if wrong_actor {
                "runtime-primary-wrong-actor"
            } else {
                "runtime-primary-tool-budget"
            },
            0x41,
            "resp_runtime_negative",
            if wrong_actor {
                "forged-runtime"
            } else {
                "runne-runtime"
            },
        );
        let prepared = super::support::prepare_fixture(
            fixture,
            "resp_runtime_negative",
            ProviderRemoteResponseStatus::Completed {
                usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
            },
            Some("synthetic text"),
        );
        if !wrong_actor {
            let identity = &prepared.fixture.claim_identity;
            prepared
                .fixture
                .database
                .connection()
                .execute(
                    "INSERT INTO taskrun_tool_budgets VALUES(?1,?2,?3,?4,?5,?6,?7,
                 'd2-safe-tool-loop-budget-v1',2,2,0,0,1)",
                    rusqlite::params![
                        identity.taskrun_id.as_bytes(),
                        identity.attempt_id.as_bytes(),
                        identity.fence.0,
                        identity.node_id.0,
                        identity.node_epoch,
                        [55u8; 16].as_slice(),
                        [56u8; 32].as_slice()
                    ],
                )
                .unwrap();
        }
        assert!(
            prepared
                .committer
                .commit_authenticated_remote_terminal_source(
                    prepared.recovery,
                    &super::support::Price
                )
                .is_err()
        );
    }
}
