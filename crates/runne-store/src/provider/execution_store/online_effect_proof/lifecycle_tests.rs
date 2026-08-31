use std::sync::Arc;
use std::sync::Barrier;

use runne_application::provider::{
    ProviderExecutionError, ProviderExecutionStore, ProviderJournalKeyBinding,
};
use rusqlite::Connection;

use crate::provider::credential_lifecycle::online_claim_test_support::reopen_test_store;
use crate::provider::credential_lifecycle::online_test_support::complete_pair;
use crate::provider::execution_store::authority_test_support::{
    Fixture, prepare_request_for_provider,
};
use crate::provider::execution_store::{
    ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore,
};

#[test]
fn rotation_installs_v2_for_new_issuance_and_rejects_v1_pre_effect() {
    let fixture = Fixture::new(100);
    fixture.install();
    let v1 = proof_binding(1);
    let keyring =
        super::super::online_proof_test_support::TestKeyring::new([(1, [7; 32]), (2, [8; 32])]);
    fixture
        .store
        .activate_journal_key_with_keyring(&keyring, v1)
        .unwrap();
    let lifecycle = reopen_test_store(&fixture.path, 100);
    complete_pair(&lifecycle, 81, "proof-rotate");
    let request = prepare_request_for_provider(fixture.launch(), &fixture.path, 81, "openai");
    let admission = match fixture.store.issue(fixture.launch(), &request).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh V1 issue required"),
    };
    let v1_claim = admission.into_claim();
    fixture
        .store
        .activate_journal_key_with_keyring(&keyring, proof_binding(2))
        .unwrap();

    let v2_request = prepare_request_for_provider(fixture.launch(), &fixture.path, 82, "openai");
    let v2_claim = match fixture.store.issue(fixture.launch(), &v2_request).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission.into_claim(),
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh V2 issue required"),
    };
    let binding = lifecycle
        .authorize_online_dispatch(fixture.launch(), &v1_claim, 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    assert!(matches!(
        fixture
            .store
            .start_online_effect(fixture.launch(), &v1_claim, &effect_binding),
        Err(runne_application::provider::ProviderAdmissionError::AuthorityDenied)
    ));
    assert_eq!(proof_versions_and_starts(&fixture.path), (1, 1, 0, 0, 0));

    let binding = lifecycle
        .authorize_online_dispatch(fixture.launch(), &v2_claim, 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    fixture
        .store
        .start_online_effect(fixture.launch(), &v2_claim, &effect_binding)
        .expect("the active V2 issuance must start exactly once");
    assert_eq!(proof_versions_and_starts(&fixture.path), (1, 1, 1, 1, 1));
}

#[test]
fn durable_v1_proof_reference_blocks_retired_key_removal_and_reloads() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let v1 = proof_binding(1);
    let keyring =
        super::super::online_proof_test_support::TestKeyring::new([(1, [7; 32]), (2, [8; 32])]);
    fixture
        .store
        .activate_journal_key_with_keyring(&keyring, v1)
        .unwrap();
    assert!(matches!(
        fixture.issue(82),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
    fixture
        .store
        .activate_journal_key_with_keyring(&keyring, proof_binding(2))
        .unwrap();

    assert_eq!(fixture.store.journal_key_reference_count(v1).unwrap(), 1);
    assert_eq!(
        fixture.store.remove_retired_journal_key(v1),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
    let Fixture {
        directory,
        path,
        store,
        ..
    } = fixture;
    drop(store);
    let reopened = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 1_000)).unwrap();
    super::super::online_proof_test_support::install_with(
        &reopened,
        2,
        [(1, [7; 32]), (2, [8; 32])],
    );
    assert_eq!(reopened.journal_key_reference_count(v1).unwrap(), 1);
    drop(directory);
}

#[test]
fn rotation_with_an_unavailable_retained_proof_key_preserves_the_active_binding() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let v1 = proof_binding(1);
    let complete =
        super::super::online_proof_test_support::TestKeyring::new([(1, [7; 32]), (2, [8; 32])]);
    fixture
        .store
        .activate_journal_key_with_keyring(&complete, v1)
        .unwrap();
    assert!(matches!(
        fixture.issue(83),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));

    let missing_v1 = super::super::online_proof_test_support::TestKeyring::new([(2, [8; 32])]);
    assert_eq!(
        fixture
            .store
            .activate_journal_key_with_keyring(&missing_v1, proof_binding(2)),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
    assert_eq!(
        fixture.store.active_journal_key_binding().unwrap(),
        Some(v1)
    );
}

#[test]
fn rotation_serializes_an_issue_waiting_behind_proof_preload() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let request = prepare_request_for_provider(fixture.launch(), &fixture.path, 84, "openai");
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let keyring =
        super::super::online_proof_test_support::TestKeyring::new([(1, [7; 32]), (2, [8; 32])])
            .block_on_load(2, Arc::clone(&reached), Arc::clone(&release));

    std::thread::scope(|scope| {
        let rotation = scope.spawn(|| {
            fixture
                .store
                .activate_journal_key_with_keyring(&keyring, proof_binding(2))
        });
        reached.wait();
        let issuance = scope.spawn(|| fixture.store.issue(fixture.launch(), &request));
        release.wait();
        rotation.join().unwrap().unwrap();
        assert!(matches!(
            issuance.join().unwrap(),
            Ok(ProviderAuthorityIssueOutcome::Winner(_))
        ));
    });
    assert_eq!(proof_versions_and_starts(&fixture.path), (0, 1, 0, 0, 0));
}

fn proof_binding(version: u64) -> ProviderJournalKeyBinding {
    ProviderJournalKeyBinding::new([9; 16], version, [1; 16], 7).unwrap()
}

fn proof_versions_and_starts(path: &std::path::Path) -> (i64, i64, i64, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_online_dispatch_issuance_evidence
                       WHERE journal_key_version = 1),
                    (SELECT COUNT(*) FROM provider_online_dispatch_issuance_evidence
                       WHERE journal_key_version = 2),
                    (SELECT COUNT(*) FROM provider_effect_starts),
                    (SELECT COUNT(*) FROM provider_online_credential_effect_bindings),
                    (SELECT COUNT(*) FROM security_audit_pre_effect)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap()
}
