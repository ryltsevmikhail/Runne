use super::*;

#[test]
fn legacy_cleanup_binding_rejects_multiple_matching_imports() {
    let store = store();
    let cleanup = complete_import(&store);
    let connection = store.connection.lock().unwrap();
    // Corrupt only this disposable test database; production insertion guards remain intact.
    let triggers: Vec<String> = connection.prepare(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='provider_credential_operations'"
    ).unwrap().query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
    for trigger in triggers {
        connection
            .execute_batch(&format!(
                "DROP TRIGGER \"{}\"",
                trigger.replace('"', "\"\"")
            ))
            .unwrap();
    }
    let columns: Vec<String> = connection
        .prepare("PRAGMA table_info(provider_credential_operations)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let selected: Vec<String> = columns
        .iter()
        .map(|column| match column.as_str() {
            "operation_id" => "?1".to_owned(),
            "command_id" => "?2".to_owned(),
            "begin_proof_digest" => "?4".to_owned(),
            "idempotency_key" => "'corrupt-duplicate-import'".to_owned(),
            _ => format!("\"{}\"", column.replace('"', "\"\"")),
        })
        .collect();
    connection.execute(&format!(
        "INSERT INTO provider_credential_operations SELECT {} FROM provider_credential_operations WHERE operation_id=?3",
        selected.join(", ")
    ), rusqlite::params![operation(90).as_bytes().as_slice(), [91_u8;16].as_slice(), operation(60).as_bytes().as_slice(), digest(92).as_bytes().as_slice()]).unwrap();
    let matches: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_credential_operations WHERE action='MIGRATE_LEGACY' AND state='COMPLETED' AND readback_observation_digest=?1",
        [digest(65).as_bytes().as_slice()], |row| row.get(0)).unwrap();
    assert_eq!(matches, 2);
    drop(connection);
    assert_eq!(
        ProviderCredentialEnrollmentStore::load_operation(&store, cleanup),
        Err(CredentialLifecycleError::CorruptState)
    );
}
