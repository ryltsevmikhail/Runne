use super::super::output_helpers::{assert_pending_output, expected_binding};
use super::super::support::Prepared;
use runne_application::provider::{
    ProviderRemoteAccountingProjection as Accounting, ProviderRemoteLocalDisposition as Local,
};
use runne_provider::{ProviderRemoteResponseStatus, ProviderUsage};

pub(super) fn assert_before_source(
    prepared: &Prepared,
    snapshot: &runne_application::ports::TaskRunEffectsReadSnapshot,
) {
    assert_eq!(snapshot.effects.taskrun_id, prepared.fixture.taskrun_id);
    assert_eq!(snapshot.effects.stream_version, prepared.fixture.version);
    assert_eq!(
        snapshot.effects.attempt_id,
        Some(prepared.fixture.claim_identity.attempt_id)
    );
    let remote = snapshot
        .remote
        .as_ref()
        .expect("authenticated remote artifact");
    assert_eq!(remote.binding, expected_binding(prepared));
    assert_eq!(remote.local_disposition, Local::Pending);
    assert_eq!(
        remote.fact.as_ref().unwrap().status(),
        &ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        }
    );
    assert!(remote.fact.as_ref().unwrap().output_digest().is_some());
    assert_eq!(remote.accounting, Accounting::Unknown);
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Withheld
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Unknown
    );
    assert_eq!(snapshot.effects.remote.usage_known, Some(true));
}

pub(super) fn assert_after_source(
    prepared: &Prepared,
    snapshot: &runne_application::ports::TaskRunEffectsReadSnapshot,
) {
    assert_pending_output(prepared, snapshot);
    assert_eq!(
        snapshot.effects.stream_version, prepared.fixture.version,
        "provider-side Source2 leaves TaskRun history unchanged"
    );
}

pub(super) fn source_counts(prepared: &Prepared) -> (i64, i64, i64, i64, i64) {
    prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_budget_reservations b
                     WHERE b.provider_idempotency_key=(SELECT provider_idempotency_key FROM provider_dispatch_attempts WHERE attempt_id=?1)
                       AND b.state=1),
                    (SELECT COUNT(*) FROM provider_budget_reservations b
                     WHERE b.provider_idempotency_key=(SELECT provider_idempotency_key FROM provider_dispatch_attempts WHERE attempt_id=?1)
                       AND b.state=2)",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap()
}
