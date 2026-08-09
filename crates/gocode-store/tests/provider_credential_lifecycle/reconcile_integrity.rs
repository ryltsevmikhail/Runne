use gocode_provider::{CredentialLifecycleError, ProviderCredentialVersionStore};
use rusqlite::Connection;

use super::support::*;

#[test]
fn reconcile_validates_every_retired_row_before_selecting_transitions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("all-retired-before-selection.sqlite");
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
