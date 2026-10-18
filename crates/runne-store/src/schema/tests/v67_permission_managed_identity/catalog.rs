use super::super::*;
use super::support::{CHALLENGE_IDENTITY, RECEIPT_IDENTITY};

#[test]
fn v67_is_an_exact_catalog_after_the_exact_v66_boundary() {
    let old = super::support::open_v66();
    assert_eq!(schema_marker(&old), 66);
    assert!(v66_matches(&old, 66).unwrap());
    assert!(!v67_matches(&old, 67).unwrap());
    apply_migrations_internal(&old, 67).unwrap();
    assert_eq!(schema_marker(&old), 67);
    assert!(v67_matches(&old, 67).unwrap());
    assert!(!v66_matches(&old, 66).unwrap());
    assert!(classify_schema_version(&old).is_ok());
}

#[test]
fn v67_rejects_metadata_table_and_trigger_drift() {
    for object in [CHALLENGE_IDENTITY, RECEIPT_IDENTITY] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 67).unwrap();
        connection
            .execute_batch(&format!("DROP TABLE {object}"))
            .unwrap();
        assert!(!v67_matches(&connection, 67).unwrap(), "{object}");
    }
    for trigger in [
        "permission_mode_native_challenge_managed_identity_immutable",
        "permission_mode_command_receipt_managed_identity_immutable",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 67).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v67_matches(&connection, 67).unwrap(), "{trigger}");
    }
}

#[test]
fn v67_rejects_future_and_noncanonical_marker_rows() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 67).unwrap();
    connection
        .execute("UPDATE schema_version SET version=68 WHERE version=67", [])
        .unwrap();
    assert!(!v67_matches(&connection, 67).unwrap());
    assert!(classify_schema_version(&connection).is_err());
}

#[test]
fn v67_accepts_only_the_exact_full_and_omitted_v19_markers() {
    let full = Connection::open_in_memory().unwrap();
    apply_migrations_through_v19_for_test(&full).unwrap();
    apply_migrations_internal(&full, 67).unwrap();
    assert_eq!(marker_tuple(&full), (67, 1, 67, 2278));
    assert!(v67_matches(&full, 67).unwrap());

    let omitted = super::support::open_v66();
    assert_eq!(marker_tuple(&omitted), (66, 1, 65, 2192));
    assert!(v66_matches(&omitted, 66).unwrap());
    apply_migrations_internal(&omitted, 67).unwrap();
    assert_eq!(marker_tuple(&omitted), (67, 1, 66, 2259));
    assert!(v67_matches(&omitted, 67).unwrap());
}

fn marker_tuple(connection: &Connection) -> (i64, i64, i64, i64) {
    connection
        .query_row(
            "SELECT MAX(version),MIN(version),COUNT(*),SUM(version) FROM schema_version",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}
