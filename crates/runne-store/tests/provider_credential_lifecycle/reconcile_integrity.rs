use runne_provider::{CredentialLifecycleError, ProviderCredentialVersionStore};
use rusqlite::Connection;

use super::support::*;

#[test]
fn reconcile_validates_every_retired_row_before_selecting_transitions() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("all-retired-before-selection.sqlite")
    };
    let lifecycle = store(&path);
    for (number, owner, fence) in [(1, OWNER_A, 101), (2, OWNER_B, 102), (3, OWNER_A, 103)] {
        let reference = version(number);
        prepare(&lifecycle, reference.clone());
        lifecycle
            .activate(lease(reference.clone(), owner, 500, fence))
            .unwrap();
        revoke(&lifecycle, reference, fence);
    }

    corrupt_retired_eligibility(&path);

    assert_eq!(
        lifecycle.reconcile(100).unwrap_err(),
        CredentialLifecycleError::CorruptState
    );
    let connection = Connection::open(&path).unwrap();
    let states = connection
        .prepare(
            "SELECT credential_version, lifecycle_state
             FROM provider_credential_versions ORDER BY credential_version",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        states,
        [
            (1, "RETIRED".into()),
            (2, "RETIRED".into()),
            (3, "RETIRED".into())
        ]
    );
}

fn corrupt_retired_eligibility(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    let triggers = [
        "provider_credential_transition_order",
        "provider_credential_identity_immutable",
    ]
    .map(|name| {
        connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
    });
    connection
        .execute_batch(
            "DROP TRIGGER provider_credential_transition_order;
             DROP TRIGGER provider_credential_identity_immutable;
             PRAGMA ignore_check_constraints=ON;
             UPDATE provider_credential_versions
             SET lease_expires_at=1000, revocation_fence=0
             WHERE credential_version=2;
             UPDATE provider_credential_versions
             SET lease_expires_at=NULL, revocation_fence=0
             WHERE credential_version=3;
             PRAGMA ignore_check_constraints=OFF;",
        )
        .unwrap();
    for trigger in triggers {
        connection.execute_batch(&trigger).unwrap();
    }
}

#[test]
fn reconcile_late_corruption_precedes_every_clock_or_lifecycle_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("late-corruption-tripwire.sqlite")
    };
    let lifecycle = store(&path);
    for (number, owner, fence) in [(1, OWNER_A, 111), (2, OWNER_B, 112)] {
        let reference = version(number);
        prepare(&lifecycle, reference.clone());
        lifecycle
            .activate(lease(reference.clone(), owner, 500, fence))
            .unwrap();
        revoke(&lifecycle, reference, fence);
    }
    corrupt_ref_digest(&path, 2);
    install_reconcile_mutation_tripwires(&path);

    assert_eq!(
        lifecycle.reconcile(100).unwrap_err(),
        CredentialLifecycleError::CorruptState
    );
    assert_reconcile_state(&path, 100);
}

#[test]
fn reconcile_reports_late_corruption_before_stale_provider_clock() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("late-corruption-stale-clock.sqlite")
    };
    let lifecycle =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_at(&path, 200).unwrap();
    for (number, owner, fence) in [(1, OWNER_A, 121), (2, OWNER_B, 122)] {
        let reference = version(number);
        prepare(&lifecycle, reference.clone());
        lifecycle
            .activate(lease(reference.clone(), owner, 500, fence))
            .unwrap();
        revoke(&lifecycle, reference, fence);
    }
    corrupt_ref_digest(&path, 2);

    assert_eq!(
        lifecycle.reconcile(100).unwrap_err(),
        CredentialLifecycleError::CorruptState
    );
    assert_reconcile_state(&path, 200);
}

fn install_reconcile_mutation_tripwires(path: &std::path::Path) {
    Connection::open(path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER test_reconcile_clock_insert
             BEFORE INSERT ON provider_credential_clock_high_water
             BEGIN SELECT RAISE(ABORT, 'clock mutation before validation'); END;
             CREATE TRIGGER test_reconcile_clock_update
             BEFORE UPDATE ON provider_credential_clock_high_water
             BEGIN SELECT RAISE(ABORT, 'clock mutation before validation'); END;
             CREATE TRIGGER test_reconcile_lifecycle_update
             BEFORE UPDATE ON provider_credential_versions
             BEGIN SELECT RAISE(ABORT, 'lifecycle mutation before validation'); END;",
        )
        .unwrap();
}

fn assert_reconcile_state(path: &std::path::Path, expected_clock: i64) {
    let connection = Connection::open(path).unwrap();
    let clock: i64 = connection
        .query_row(
            "SELECT observed_at FROM provider_credential_clock_high_water
             WHERE provider_id='openai'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(clock, expected_clock);
    for number in [1, 2] {
        let state: String = connection
            .query_row(
                "SELECT lifecycle_state FROM provider_credential_versions
                 WHERE provider_id='openai' AND credential_version=?1",
                [number],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "RETIRED");
    }
}
