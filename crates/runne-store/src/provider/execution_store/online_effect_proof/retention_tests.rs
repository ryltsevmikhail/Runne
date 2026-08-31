use std::sync::Arc;

use runne_application::provider::{ProviderExecutionStore, ProviderJournalKeyBinding};
use rusqlite::Connection;

use super::IssuanceProofFields;
use crate::provider::execution_store::authority_test_support::{
    Fixture, config, configured_connection, prepare_request,
};
use crate::provider::execution_store::{
    ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore,
};

#[test]
fn reopens_all_thirty_three_durable_proof_keys_and_validates_the_oldest_evidence() {
    let mut fixture = Fixture::new(1_000);
    fixture.config.token_budget_limit = 100_000;
    fixture.config.cost_budget_limit_micros = 2_000_000;
    fixture.install();
    let keyring = super::super::online_proof_test_support::TestKeyring::new(keys());
    fixture
        .store
        .activate_journal_key_with_keyring(&keyring, binding(1))
        .unwrap();
    assert!(matches!(
        fixture.store.issue(
            fixture.launch(),
            &prepare_request(fixture.launch(), &fixture.path, 1),
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

    for version in 2..=33 {
        let store = reopen(&path);
        let launch_config = wide_config();
        let launch = store.activate_runtime_launch(&launch_config).unwrap();
        let keyring = super::super::online_proof_test_support::TestKeyring::new(keys());
        store
            .install_online_effect_proof_capability(&keyring, binding(version - 1))
            .unwrap();
        store
            .activate_journal_key_with_keyring(&keyring, binding(version))
            .unwrap();
        let issuance = store.issue(&launch, &prepare_request(&launch, &path, version as u8));
        assert!(
            matches!(issuance, Ok(ProviderAuthorityIssueOutcome::Winner(_))),
            "V{version} issuance: {issuance:?}"
        );
    }

    let reopened = reopen(&path);
    let keyring = super::super::online_proof_test_support::TestKeyring::new(keys());
    reopened
        .install_online_effect_proof_capability(&keyring, binding(33))
        .expect("every durable evidence key must be retained on restart");
    let (fields, mac) = oldest_issuance(&path);
    assert!(
        reopened
            .online_effect_proof
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .verify_issue(&fields, &mac),
        "the oldest V1 issuance evidence must remain verifiable"
    );
    drop(directory);
}

#[test]
fn restart_with_v2_rejects_retired_v1_install_and_verifies_v1_issuance() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let keyring = super::super::online_proof_test_support::TestKeyring::new(keys());
    assert!(matches!(
        fixture.store.issue(
            fixture.launch(),
            &prepare_request(fixture.launch(), &fixture.path, 34),
        ),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
    fixture
        .store
        .activate_journal_key_with_keyring(&keyring, binding(2))
        .unwrap();
    let Fixture {
        directory,
        path,
        store,
        ..
    } = fixture;
    drop(store);

    let reopened = reopen(&path);
    assert_eq!(
        reopened.install_online_effect_proof_capability(&keyring, binding(1)),
        Err(runne_application::provider::ProviderAdmissionError::AuthorityDenied)
    );
    reopened
        .install_online_effect_proof_capability(&keyring, binding(2))
        .unwrap();
    let (fields, mac) = oldest_issuance(&path);
    assert!(
        reopened
            .online_effect_proof
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .verify_issue(&fields, &mac)
    );
    drop(directory);
}

fn reopen(path: &std::path::Path) -> SqliteProviderExecutionStore {
    SqliteProviderExecutionStore::open_with_connection_and_now(
        path.to_str().unwrap(),
        configured_connection(path),
        Arc::new(|| 1_000),
    )
    .unwrap()
}

fn binding(version: u64) -> ProviderJournalKeyBinding {
    ProviderJournalKeyBinding::new([9; 16], version, [1; 16], 7).unwrap()
}

fn keys() -> impl Iterator<Item = (u64, [u8; 32])> {
    (1..=33).map(|version| {
        let bytes = if version == 1 {
            [7; 32]
        } else {
            [version as u8; 32]
        };
        (version, bytes)
    })
}

fn wide_config() -> crate::provider::ProviderRuntimeAuthorityConfig {
    let mut config = config();
    config.token_budget_limit = 100_000;
    config.cost_budget_limit_micros = 2_000_000;
    config
}

fn oldest_issuance(path: &std::path::Path) -> (IssuanceProofFields, [u8; 32]) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT evidence.provider_id, admission.provider_idempotency_key, admission.semantic_digest,
                    admission.call_id, admission.dispatch_attempt_id, admission.authority_id,
                    admission.authority_revision, admission.permit_id,
                    admission.token_reservation_id, admission.cost_reservation_id,
                    admission.runtime_authority_id, admission.database_generation,
                    admission.generation, admission.fencing_token, admission.prepared_digest,
                    admission.render_digest, admission.profile_digest,
                    admission.pricing_revision_digest, admission.issued_at, admission.expires_at,
                    evidence.issuance_mac
               FROM provider_execution_admissions admission
               JOIN provider_online_dispatch_issuance_evidence evidence
                 ON evidence.dispatch_attempt_id = admission.dispatch_attempt_id
              WHERE evidence.journal_key_version = 1",
            [],
            |row| {
                Ok((
                    IssuanceProofFields {
                        proof_version: 1,
                        key: binding(1),
                        runtime_authority_id: array(row, 10)?,
                        database_generation: number(row, 11)?,
                        provider_id: row.get(0)?,
                        provider_idempotency_key: row.get(1)?,
                        semantic_digest: array(row, 2)?,
                        call_id: array(row, 3)?,
                        attempt_id: array(row, 4)?,
                        authority_id: array(row, 5)?,
                        authority_revision: number(row, 6)?,
                        permit_id: array(row, 7)?,
                        token_reservation_id: array(row, 8)?,
                        cost_reservation_id: array(row, 9)?,
                        generation: number(row, 12)?,
                        fencing_token: number(row, 13)?,
                        prepared_digest: array(row, 14)?,
                        render_digest: array(row, 15)?,
                        profile_digest: array(row, 16)?,
                        pricing_revision_digest: array(row, 17)?,
                        issued_at: row.get(18)?,
                        expires_at: row.get(19)?,
                    },
                    array(row, 20)?,
                ))
            },
        )
        .unwrap()
}

fn array<const N: usize>(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    row.get::<_, Vec<u8>>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn number(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
