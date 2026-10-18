use std::sync::Arc;

use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, ClaimCredentialOperation,
    CredentialBrokerCommand, CredentialFence, CredentialLifecycleRevision,
    CredentialMeasurementSnapshot, CredentialOperationAction, CredentialOperationId,
    CredentialSecretClaimOffer, ProviderCredentialEnrollmentStore, ProviderId,
};
use runne_store::provider::online_claim_test_support::open_test_store_with_authorities;

use super::super::broker::ProviderCredentialBroker;
use super::super::broker::issue::ClaimIssueContext;
use super::nested_db;

#[path = "broker_support/recording_channel.rs"]
mod recording_channel;
pub(crate) use recording_channel::RecordingChannel;

/// Deterministic clock base for the broker fixtures: the paired-authority
/// store's fixed verification clock, the begin expiry margin, and the cleanup
/// recovery lease all anchor here, so no fixture domain reads the wall clock.
/// Each fixture owns its store instance; the shared immutable base cannot
/// race under concurrent test execution.
pub(crate) const FIXTURE_NOW_SECONDS: i64 = 100;

/// Begin high-water margin over the fixture clock, kept at the historical
/// fixture margin but anchored to the deterministic base.
pub(crate) const BEGIN_EXPIRY_MARGIN_SECONDS: i64 = 600;

pub(crate) struct Fixture {
    // Read by the unix broker transport scenarios only.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) enrollment_authority: runne_provider::CredentialEnrollmentStoreAuthority,
    pub(in crate::application::provider_credential_enrollment) broker: ProviderCredentialBroker,
    pub(crate) measurements: Arc<runne_provider::CredentialEnrollmentMeasurementAuthority>,
    pub(crate) store: runne_store::provider::SqliteProviderCredentialLifecycleStore,
    pub(crate) operation: runne_provider::CredentialOperationSnapshot,
    pub(crate) continuation: runne_provider::CredentialBindingDigest,
    pub(crate) _directory: tempfile::TempDir,
}

pub(crate) fn fixture() -> Fixture {
    fixture_with_action(CredentialOperationAction::Pair, "broker-ticket")
}

/// Wall-clock twin for consumers whose production path itself anchors on the
/// real clock (the control-facade recovery session mixes
/// `SystemTime::now` into its offer high-water); keeps their historical
/// semantics while the broker tests run on the deterministic fixture clock.
pub(crate) fn wall_clock_fixture() -> Fixture {
    fixture_with_action_at(CredentialOperationAction::Pair, "broker-ticket", None)
}

/// Fixture for one claimed migrate operation: the same begin shape as Pair
/// (allocated version, no target) but no secret offer, so the claimed effect
/// carries no secret relay.
pub(crate) fn migrate_fixture() -> Fixture {
    fixture_with_action(CredentialOperationAction::MigrateLegacy, "broker-migrate")
}

fn fixture_with_action(action: CredentialOperationAction, idempotency: &str) -> Fixture {
    fixture_with_action_at(action, idempotency, Some(FIXTURE_NOW_SECONDS))
}

pub(crate) fn fixture_with_action_at(
    action: CredentialOperationAction,
    idempotency: &str,
    store_now: Option<i64>,
) -> Fixture {
    assert!(matches!(
        action,
        CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy
    ));
    let directory = tempfile::tempdir().unwrap();
    let database = nested_db(directory.path(), "broker.sqlite");
    let (store, enrollment, measurements) = match store_now {
        Some(now) => open_test_store_with_authorities(&database, now),
        None => {
            let (lifecycle, _) = runne_provider::CredentialAuthorityPair::new().split();
            let (enrollment, measurements) =
                runne_provider::CredentialEnrollmentAuthorityPair::new().split();
            let store =
                runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
                    &database,
                    lifecycle,
                    enrollment.clone(),
                )
                .unwrap();
            (store, enrollment, measurements)
        }
    };
    let measurements = Arc::new(measurements);
    let provider = ProviderId::new("openai").unwrap();
    let qualified = measurements
        .issue_qualified_credential_release_tuple(
            measurements.release_manifest_digest([9; 32]).unwrap(),
        )
        .unwrap();
    let expiration = match store_now {
        Some(now) => u64::try_from(now + BEGIN_EXPIRY_MARGIN_SECONDS).unwrap(),
        None => {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + u64::try_from(BEGIN_EXPIRY_MARGIN_SECONDS).unwrap()
        }
    };
    let input = BeginCredentialOperation::new(
        CommandId::from_bytes([1; 16]),
        IdempotencyKey::new(idempotency).unwrap(),
        CredentialOperationId::from_bytes([2; 16]).unwrap(),
        runne_provider::CredentialInstallationOwnerId::from_bytes([3; 32]).unwrap(),
        provider.clone(),
        action,
        Some(runne_provider::CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        runne_provider::CredentialBindingDigest::from_measured([4; 32]).unwrap(),
        expiration,
    )
    .unwrap()
    .with_qualified_release_tuple(qualified);
    let input = match action {
        CredentialOperationAction::MigrateLegacy => {
            let authorization = enrollment
                .issue_legacy_import_authorization(&input)
                .unwrap();
            input
                .with_legacy_import_authorization(authorization)
                .unwrap()
        }
        _ => input,
    };
    let operation = match store.begin(input).unwrap() {
        BeginCredentialOperationOutcome::FreshWinner(value) => value,
        BeginCredentialOperationOutcome::ExactReplay(_) => panic!("first begin must win"),
    };
    Fixture {
        enrollment_authority: enrollment,
        broker: ProviderCredentialBroker::new(measurements.clone()),
        measurements,
        store,
        operation,
        continuation: runne_provider::CredentialBindingDigest::from_measured([5; 32]).unwrap(),
        _directory: directory,
    }
}

pub(crate) fn issue_context(fixture: &Fixture) -> ClaimIssueContext {
    issue_context_for(fixture, fixture.continuation)
}

pub(crate) fn issue_context_for(
    fixture: &Fixture,
    continuation: runne_provider::CredentialBindingDigest,
) -> ClaimIssueContext {
    fixture
        .broker
        .claim_issue_context(
            claim_measurements_for(&fixture.measurements, continuation, 8),
            [21; 32],
            continuation,
            7,
            8,
        )
        .unwrap()
}

pub(crate) fn claim_measurements(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
) -> CredentialMeasurementSnapshot {
    claim_measurements_for(
        authority,
        claim.continuation_binding_digest(),
        claim.desktop_supervisor_generation(),
    )
}

pub(crate) fn claim_measurements_for(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    continuation: runne_provider::CredentialBindingDigest,
    desktop_supervisor_generation: u64,
) -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([10; 32]).unwrap(),
        authority.release_manifest_digest([11; 32]).unwrap(),
        authority.desktop_executable_identity([12; 32]).unwrap(),
        authority.writer_executable_identity([13; 32]).unwrap(),
        authority.reader_executable_identity([14; 32]).unwrap(),
        authority.contract_bundle_digest([15; 32]).unwrap(),
        authority.daemon_authority_id([16; 32]).unwrap(),
        authority.protected_session_id([17; 32]).unwrap(),
        authority
            .desktop_supervisor_generation(desktop_supervisor_generation)
            .unwrap(),
        authority.writer_launch_id([18; 32]).unwrap(),
        authority.writer_process_start_identity([19; 32]).unwrap(),
        authority.writer_process_handle_identity([20; 32]).unwrap(),
        authority.broker_channel_binding([21; 32]).unwrap(),
        authority
            .continuation_binding_digest(continuation.as_bytes())
            .unwrap(),
    )
    .unwrap()
}

pub(crate) fn pair_offer(
    receipt: &runne_provider::IssuedCredentialTicketAttempt,
    binding: runne_provider::CredentialBindingDigest,
) -> CredentialSecretClaimOffer {
    let command =
        CredentialBrokerCommand::from_operation(receipt.operation(), receipt.ticket_attempt())
            .unwrap();
    CredentialSecretClaimOffer::prepare(&command, binding)
        .unwrap()
        .0
}
