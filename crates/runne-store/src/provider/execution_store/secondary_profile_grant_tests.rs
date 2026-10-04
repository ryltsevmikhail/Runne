use runne_application::provider::{
    ProviderEncryptedPayload, ProviderExecutionStore, ProviderPollRequest,
    ProviderTerminalCommitOutcome,
};
use runne_provider::{ProviderId, ProviderStreamId};
use rusqlite::Connection;

use super::ProviderAuthorityIssueOutcome;
use super::authority_test_support::{Fixture, prepare_request_for_provider};
#[path = "secondary_profile_grant_online_helpers.rs"]
mod online_helpers;
pub(super) use online_helpers::start_online_stream;

pub(super) fn secondary_fixture() -> Fixture {
    let mut fixture = Fixture::new(1_000);
    fixture.config.profile_digest = [22; 32];
    fixture.config.pricing_revision_digest = [33; 32];
    fixture.install();
    fixture
}

pub(super) fn secondary_online_fixture() -> (
    Fixture,
    crate::provider::SqliteProviderCredentialLifecycleStore,
) {
    use crate::provider::credential_lifecycle::online_test_support::complete_pair;

    let (mut fixture, lifecycle) = Fixture::new_with_online_credentials(100, |lifecycle| {
        complete_pair(lifecycle, 74, "secondary-online-effect");
    });
    fixture.config.profile_digest = [22; 32];
    fixture.config.pricing_revision_digest = [33; 32];
    fixture.install();
    (fixture, lifecycle)
}

pub(super) fn grant(fixture: &Fixture, provider: &str) -> super::ProviderSecondaryProfileGrant {
    let id = ProviderId::new(provider).unwrap();
    let spec = runne_application::provider::ProviderSecondaryProfileGrantSpec::new(
        &id,
        "background-text-v1",
        provider,
        [2; 32],
        [3; 32],
        5_000,
        500_000,
    )
    .unwrap();
    fixture
        .store
        .install_secondary_profile_grant(fixture.launch(), spec)
        .unwrap()
}

pub(super) fn issue(
    fixture: &Fixture,
    grant: &super::ProviderSecondaryProfileGrant,
    provider: &str,
    discriminator: u8,
) -> super::ProviderAuthorityIssueOutcome {
    let request =
        prepare_request_for_provider(fixture.launch(), &fixture.path, discriminator, provider);
    fixture
        .store
        .issue_secondary_profile(fixture.launch(), grant, &request)
        .unwrap()
}

#[path = "secondary_profile_grant_publication_tests.rs"]
mod publication_tests;

#[path = "secondary_profile_grant_runtime_settlement.rs"]
pub(super) mod runtime_settlement;

pub(super) fn encrypted(nonce: u8, byte: u8) -> ProviderEncryptedPayload {
    ProviderEncryptedPayload::new([nonce; 12], vec![byte; 32], 16, [byte; 32]).unwrap()
}

pub(super) fn append_terminal(fixture: &Fixture, admission: &super::DurableProviderAdmission) {
    runtime_settlement::journal_only(fixture, admission);
}

pub(super) fn winner(
    outcome: ProviderAuthorityIssueOutcome,
) -> Box<super::DurableProviderAdmission> {
    match outcome {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => {
            panic!("new secondary admission expected")
        }
    }
}

#[test]
fn secondary_admission_and_terminal_settlement_use_only_its_budget() {
    let (fixture, lifecycle) = secondary_online_fixture();
    let secondary = grant(&fixture, "openai");
    let primary_before = fixture.store.utilization().unwrap();
    let (secondary_tokens_before, secondary_cost_before) = fixture
        .store
        .secondary_profile_utilization(fixture.launch(), &secondary)
        .unwrap();
    let admission = winner(issue(&fixture, &secondary, "openai", 71));
    assert_eq!(fixture.store.utilization().unwrap(), primary_before);
    let (tokens, cost) = fixture
        .store
        .secondary_profile_utilization(fixture.launch(), &secondary)
        .unwrap();
    assert_eq!(
        (tokens.limit, tokens.reserved, tokens.settled),
        (5_000, 1_536, 0)
    );
    assert_eq!(
        (cost.limit, cost.reserved, cost.settled),
        (500_000, 50_000, 0)
    );
    assert_eq!(secondary_tokens_before.remaining, 5_000);
    assert_eq!(secondary_cost_before.remaining, 500_000);

    start_online_stream(&fixture, &lifecycle, &admission);
    assert_eq!(
        runtime_settlement::settle(&fixture, &admission),
        ProviderTerminalCommitOutcome::Committed
    );
    assert_eq!(
        runtime_settlement::finalize(&fixture, &admission),
        ProviderTerminalCommitOutcome::Replayed
    );
    let (tokens, cost) = fixture
        .store
        .secondary_profile_utilization(fixture.launch(), &secondary)
        .unwrap();
    assert_eq!(
        (tokens.reserved, tokens.settled, tokens.remaining),
        (0, 1_400, 3_600)
    );
    assert_eq!(
        (cost.reserved, cost.settled, cost.remaining),
        (0, 40_000, 460_000)
    );
    assert_eq!(fixture.store.utilization().unwrap(), primary_before);
}

#[test]
fn revocation_blocks_poll_but_settles_an_already_journaled_terminal() {
    let (fixture, lifecycle) = secondary_online_fixture();
    let secondary = grant(&fixture, "openai");
    let admission = winner(issue(&fixture, &secondary, "openai", 72));
    start_online_stream(&fixture, &lifecycle, &admission);
    runtime_settlement::journal_only(&fixture, &admission);
    fixture
        .store
        .revoke_secondary_profile_grant(fixture.launch(), &secondary)
        .unwrap();
    let claim = admission.claim();
    assert!(
        fixture
            .store
            .begin_provider_poll(&ProviderPollRequest {
                attempt_id: claim.attempt_id,
                fencing_token: claim.fencing_token,
                cursor: 1,
                profile_digest: [2; 32],
                runtime_generation: 11,
            })
            .is_err()
    );
    assert_eq!(
        runtime_settlement::finalize(&fixture, &admission),
        ProviderTerminalCommitOutcome::Committed
    );
}

#[test]
fn secondary_effect_start_rejects_a_credential_from_another_provider_realm() {
    let fixture = secondary_fixture();
    let secondary = grant(&fixture, "openai");
    let admission = winner(issue(&fixture, &secondary, "openai", 73));
    let (_, wrong_credential) = fixture.credential();
    assert!(
        fixture
            .store
            .start_effect(admission.claim(), &wrong_credential)
            .is_err()
    );
    let rows: i64 = Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM provider_effect_starts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn online_credential_path_starts_a_secondary_profile_effect() {
    use crate::provider::credential_lifecycle::online_test_support::provider;

    let (fixture, lifecycle) = secondary_online_fixture();
    let secondary = grant(&fixture, "openai");
    let admission = winner(issue(&fixture, &secondary, "openai", 74));
    let authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), admission.claim(), 100)
        .unwrap();
    assert_eq!(provider().as_str(), "openai");
    let (_, effect_binding) = authorization.split();
    assert!(
        fixture
            .store
            .start_online_effect(fixture.launch(), admission.claim(), &effect_binding)
            .is_ok()
    );
}
