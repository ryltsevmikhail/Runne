use super::super::*;
use super::support::{CHALLENGE_IDENTITY, RECEIPT_IDENTITY};

#[test]
fn v67_metadata_has_exact_parent_foreign_keys_and_insert_only_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 67).unwrap();
    for (table, parent, key) in [
        (
            CHALLENGE_IDENTITY,
            "permission_mode_native_challenges",
            "challenge_id",
        ),
        (
            RECEIPT_IDENTITY,
            "permission_mode_command_receipts",
            "command_id",
        ),
    ] {
        let foreign_keys: i64 = connection
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM pragma_foreign_key_list('{table}')
                     WHERE \"table\"=?1 AND \"from\"=?2"
                ),
                rusqlite::params![parent, key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(foreign_keys, 1, "{table} must reference {parent}.{key}");
    }
    let violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0);
    assert!(v67_matches(&connection, 67).unwrap());
}
