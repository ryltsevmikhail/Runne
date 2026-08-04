use std::sync::Arc;

use gocode_application::provider::{ProviderAdmissionError, ProviderLeaseBindingKind};
use rusqlite::Connection;

use super::authority_test_support::{Fixture, config, prepare_request};
use super::{ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore};

const STATE_V14_COLUMNS: &[&str] = &[
    "capability_expires_at",
    "capability_revocation_epoch",
    "capability_revocation_observed",
    "approval_revocation_epoch",
    "approval_revocation_observed",
    "activation_binding_kind",
    "activation_binding_digest",
];
const ADMISSION_V14_COLUMNS: &[&str] = &[
    "owner_id",
    "scope",
    "capability_grant_id",
    "capability_revision",
    "capability_expires_at",
    "capability_revocation_epoch",
    "capability_revocation_observed",
    "approval_id",
    "approval_revision",
    "approval_expires_at",
    "approval_revocation_epoch",
    "approval_revocation_observed",
    "activation_binding_kind",
    "activation_binding_digest",
];

#[derive(Debug, PartialEq, Eq)]
struct AdmissionLeaseRow {
    owner_id: String,
    scope: String,
    capability_grant_id: String,
    capability_revision: i64,
    capability_expires_at: i64,
    capability_revocation_epoch: i64,
    capability_revocation_observed: i64,
    approval_id: String,
    approval_revision: i64,
    approval_expires_at: i64,
    approval_revocation_epoch: i64,
    approval_revocation_observed: i64,
    activation_binding_kind: String,
    activation_binding_digest: Vec<u8>,
}

#[test]
fn v14_admission_persists_the_exact_lease_and_activation_snapshot() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    assert!(matches!(
        fixture.issue(1).unwrap(),
        ProviderAuthorityIssueOutcome::Winner(_)
    ));
    let connection = Connection::open(&fixture.path).unwrap();
    let columns = table_columns(&connection, "provider_execution_admissions");
    for required in ADMISSION_V14_COLUMNS {
        assert!(
            columns.iter().any(|column| column == required),
            "missing {required}"
        );
    }
    let row = connection
        .query_row(
            "SELECT owner_id, scope, capability_grant_id, capability_revision,
                        capability_expires_at, capability_revocation_epoch,
                        capability_revocation_observed, approval_id, approval_revision,
                        approval_expires_at,
                        approval_revocation_epoch, approval_revocation_observed,
                        activation_binding_kind, activation_binding_digest
                   FROM provider_execution_admissions WHERE provider_idempotency_key = ?1",
            ["provider-v14-1"],
            |row| {
                Ok(AdmissionLeaseRow {
                    owner_id: row.get(0)?,
                    scope: row.get(1)?,
                    capability_grant_id: row.get(2)?,
                    capability_revision: row.get(3)?,
                    capability_expires_at: row.get(4)?,
                    capability_revocation_epoch: row.get(5)?,
                    capability_revocation_observed: row.get(6)?,
                    approval_id: row.get(7)?,
                    approval_revision: row.get(8)?,
                    approval_expires_at: row.get(9)?,
                    approval_revocation_epoch: row.get(10)?,
                    approval_revocation_observed: row.get(11)?,
                    activation_binding_kind: row.get(12)?,
                    activation_binding_digest: row.get(13)?,
                })
            },
        )
        .unwrap();
    assert_eq!(
        row,
        AdmissionLeaseRow {
            owner_id: "owner-1".into(),
            scope: "provider.dispatch".into(),
            capability_grant_id: "capability-1".into(),
            capability_revision: 2,
            capability_expires_at: 1_600,
            capability_revocation_epoch: 1,
            capability_revocation_observed: 0,
            approval_id: "approval-1".into(),
            approval_revision: 3,
            approval_expires_at: 1_600,
            approval_revocation_epoch: 1,
            approval_revocation_observed: 0,
            activation_binding_kind: "protected_v2".into(),
            activation_binding_digest: vec![4; 32],
        }
    );
    let authority: (Vec<u8>, i64, i64, i64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT runtime_authority_id, database_generation, generation, fencing_token,
                    profile_digest, pricing_revision_digest
             FROM provider_execution_admissions WHERE provider_idempotency_key = ?1",
            ["provider-v14-1"],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        authority,
        (vec![1; 16], 7, 11, 13, vec![2; 32], vec![3; 32])
    );
}

#[test]
fn external_owner_private_admission_persists_its_closed_activation_kind() {
    let mut fixture = Fixture::new(1_000);
    fixture.config.activation_binding_kind = ProviderLeaseBindingKind::ExternalOwnerPrivate;
    fixture.config.activation_binding_digest = [9; 32];
    fixture.install();
    assert!(fixture.issue(1).is_ok());
    let binding: (String, Vec<u8>) = Connection::open(&fixture.path)
        .unwrap()
        .query_row(
            "SELECT activation_binding_kind, activation_binding_digest
             FROM provider_execution_admissions WHERE provider_idempotency_key = ?1",
            ["provider-v14-1"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(binding, ("external_owner_private".into(), vec![9; 32]));
}

#[test]
fn reopen_retains_exact_binding_and_counters_without_reset() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    assert!(fixture.issue(1).is_ok());
    let before = fixture.store.utilization().unwrap();
    let path = fixture.path.clone();
    let _directory = fixture.directory;
    drop(fixture.store);

    let reopened = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 1_100)).unwrap();
    assert_eq!(reopened.utilization().unwrap(), before);
    let connection = Connection::open(path).unwrap();
    let binding: (String, Vec<u8>, i64, i64) = connection
        .query_row(
            "SELECT activation_binding_kind, activation_binding_digest,
                    capability_expires_at, approval_expires_at
             FROM provider_execution_admissions WHERE provider_idempotency_key = ?1",
            ["provider-v14-1"],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(binding, ("protected_v2".into(), vec![4; 32], 1_600, 1_600));
}

#[test]
fn migrated_v13_rows_are_legacy_unbound_readable_and_inactive_until_revalidated() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    assert!(fixture.issue(1).is_ok());
    let before = fixture.store.utilization().unwrap();
    let path = fixture.path.clone();
    let _directory = fixture.directory;
    drop(fixture.store);

    let connection = Connection::open(&path).unwrap();
    for column in ADMISSION_V14_COLUMNS {
        connection
            .execute(
                &format!("ALTER TABLE provider_execution_admissions DROP COLUMN {column}"),
                [],
            )
            .unwrap();
    }
    for column in STATE_V14_COLUMNS {
        connection
            .execute(
                &format!("ALTER TABLE provider_runtime_authority_state DROP COLUMN {column}"),
                [],
            )
            .unwrap();
    }
    connection
        .execute("DELETE FROM schema_version WHERE version = 14", [])
        .unwrap();
    crate::schema::provider_schema::apply_v14_migration(&connection, |_| Ok(())).unwrap();
    drop(connection);

    let reopened = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 2_000)).unwrap();
    assert_eq!(reopened.utilization().unwrap(), before);
    let legacy = Connection::open(&path).unwrap();
    let state: (i64, i64, i64, String, Vec<u8>) = legacy
        .query_row(
            "SELECT active, capability_revocation_observed, approval_revocation_observed,
                    activation_binding_kind, activation_binding_digest
             FROM provider_runtime_authority_state WHERE id = 1",
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
        .unwrap();
    assert_eq!(state, (0, 0, 0, "legacy_unbound".into(), vec![0; 32]));
    let admission: (String, Vec<u8>) = legacy
        .query_row(
            "SELECT activation_binding_kind, activation_binding_digest
             FROM provider_execution_admissions WHERE provider_idempotency_key = ?1",
            ["provider-v14-1"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(admission, ("legacy_unbound".into(), vec![0; 32]));
    drop(legacy);

    assert_eq!(
        reopened.issue(&prepare_request(&path, 1)).unwrap(),
        ProviderAuthorityIssueOutcome::Existing {
            state: gocode_provider::ProviderRepositoryState::Dispatching,
        }
    );
    assert_eq!(
        reopened.issue(&prepare_request(&path, 2)),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    reopened.install_runtime_authority(&config()).unwrap();
    assert!(reopened.issue(&prepare_request(&path, 2)).is_ok());
}

fn table_columns(connection: &Connection, table: &str) -> Vec<String> {
    connection
        .prepare(&format!("PRAGMA table_info('{table}')"))
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}
