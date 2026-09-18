use runne_application::provider::{ProviderAdmissionError, ProviderAuthorityIssueRequest};
use runne_provider::ProviderId;
use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;

use super::ProviderAuthorityIssueOutcome;
use super::authority_test_support::{Fixture, configured_connection, prepare_request};
include!("authority_replay_provider_test_support.rs");

#[test]
fn unarmed_new_online_issue_is_denied() {
    let fixture = Fixture::new_unarmed(1_000);
    let launch = fixture
        .store
        .activate_runtime_launch(&fixture.config)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .issue(&launch, &prepare_request(&launch, &fixture.path, 70)),
        Err(ProviderAdmissionError::AuthorityDenied),
        "an unarmed store must not mint a new online authority"
    );
}

#[test]
fn missing_retained_v1_key_is_checked_at_proof_capability_install_not_schema_open() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    assert!(matches!(
        fixture.store.issue(
            fixture.launch(),
            &prepare_request(fixture.launch(), &fixture.path, 72)
        ),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
    let Fixture {
        directory,
        path,
        store,
        ..
    } = fixture;
    drop(store);
    let reopened = super::SqliteProviderExecutionStore::open(&path)
        .expect("schema open remains unarmed for status/replay");
    assert!(
        reopened.online_effect_proof.get().is_none(),
        "test fixture must not auto-arm before missing-key capability admission"
    );
    let binding =
        runne_application::provider::ProviderJournalKeyBinding::new([9; 16], 2, [1; 16], 7)
            .unwrap();
    let keyring = super::online_proof_test_support::TestKeyring::new([(2, [8; 32])]);
    assert_eq!(
        reopened.install_online_effect_proof_capability(&keyring, binding),
        Err(ProviderAdmissionError::AuthorityDenied),
        "missing retained V1 proof material must close at capability install"
    );
    drop(directory);
}

#[test]
fn provider_replay_requires_an_exact_durable_mapping() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let request = prepare_request(fixture.launch(), &fixture.path, 71);
    assert!(matches!(
        fixture.store.issue(fixture.launch(), &request),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
    let before = admission_counts(&fixture.path);
    assert_eq!(
        fixture.store.issue(fixture.launch(), &request),
        Ok(ProviderAuthorityIssueOutcome::Existing {
            state: runne_provider::ProviderRepositoryState::Dispatching,
        })
    );
    let mut cross_provider = request.clone();
    cross_provider.provider_id = ProviderId::new("other-provider").unwrap();

    assert_eq!(
        fixture.store.issue(fixture.launch(), &cross_provider),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_eq!(admission_counts(&fixture.path), before);
}

#[test]
fn upgraded_v25_admission_without_provider_mapping_conflicts_without_mutation() {
    let (_directory, path, request) = upgraded_v25(74);
    let reopened = super::SqliteProviderExecutionStore::open(&path).unwrap();
    let launch = reopened
        .activate_runtime_launch(&super::authority_test_support::config())
        .unwrap();
    let fields = admission_fields(&path);
    let error = Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO provider_online_dispatch_issuance_evidence
             (dispatch_attempt_id, provider_id, authority_id, authority_revision, issued_at)
             VALUES (?1, 'other-provider', ?2, ?3, ?4)",
            (&fields.0, &fields.1, fields.2, fields.3),
        )
        .unwrap_err();
    assert!(error.to_string().contains("NOT NULL"));
    let before = admission_counts(&path);
    assert_eq!(
        reopened.issue(&launch, &request),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_eq!(admission_counts(&path), before);
}

#[test]
fn managed_writer_cannot_attach_arbitrary_provider_to_upgraded_v25_admission() {
    let (_directory, path, _) = upgraded_v25(78);
    let _reopened = super::SqliteProviderExecutionStore::open(&path).unwrap();
    let fields = admission_fields(&path);
    let managed = configured_connection(&path);
    let error = managed
        .execute(
            "INSERT INTO provider_online_dispatch_issuance_evidence
             (dispatch_attempt_id, provider_id, authority_id, authority_revision, issued_at)
             VALUES (?1, 'other-provider', ?2, ?3, ?4)",
            (&fields.0, &fields.1, fields.2, fields.3),
        )
        .unwrap_err();
    assert!(error.to_string().contains("NOT NULL"));
}

#[test]
fn store_open_restores_the_private_issuance_guard_after_caller_replaces_it() {
    let (_directory, path, _) = upgraded_v25(79);
    let caller = configured_connection(&path);
    caller
        .remove_function("runne_online_issuance_guard", 5)
        .unwrap();
    caller
        .create_scalar_function(
            "runne_online_issuance_guard",
            5,
            FunctionFlags::SQLITE_UTF8,
            |_| Ok(true),
        )
        .unwrap();
    let store = super::SqliteProviderExecutionStore::open_with_connection_and_now(
        path.to_str().unwrap(),
        caller,
        std::sync::Arc::new(|| 1_000),
    )
    .unwrap();
    super::online_proof_test_support::arm(&store);
    let launch = store
        .activate_runtime_launch(&super::authority_test_support::config())
        .unwrap();
    let fields = admission_fields(&path);
    let connection = store.connection.lock().unwrap();
    let evidence = connection.execute(
        "INSERT INTO provider_online_dispatch_issuance_evidence
         (dispatch_attempt_id, provider_id, authority_id, authority_revision, issued_at)
         VALUES (?1, 'other-provider', ?2, ?3, ?4)",
        (&fields.0, &fields.1, fields.2, fields.3),
    );
    assert!(
        evidence.is_err(),
        "restored guard must reject copied fields"
    );
    let mapping = connection.execute(
        "INSERT INTO provider_online_dispatch_claim_providers
         (dispatch_attempt_id, provider_id) VALUES (?1, 'other-provider')",
        [&fields.0],
    );
    assert!(mapping.is_err(), "restored guard must also protect mapping");
    drop(connection);

    let issue = store.issue(&launch, &prepare_request(&launch, &path, 80));
    assert!(
        matches!(issue, Ok(ProviderAuthorityIssueOutcome::Winner(_))),
        "{issue:?}"
    );
}
