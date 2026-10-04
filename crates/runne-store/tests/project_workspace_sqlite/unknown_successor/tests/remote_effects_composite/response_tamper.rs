use super::source_tamper::{assert_reopen_rejected, pending, trigger_sql};

#[test]
fn source_readiness_rejects_changed_response_and_artifact_bindings() {
    let prepared = pending("remote-v59-response-tamper", 0x94);
    let connection = prepared.fixture.database.connection();
    let trigger = trigger_sql(&connection, "provider_remote_response_bindings_immutable");
    connection
        .execute_batch("DROP TRIGGER provider_remote_response_bindings_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_remote_response_bindings SET plaintext_digest=?1
             WHERE dispatch_attempt_id=?2",
            rusqlite::params![
                [0x56_u8; 32].as_slice(),
                prepared.attempt.as_bytes().as_slice()
            ],
        )
        .unwrap();
    assert_eq!(connection.changes(), 1);
    connection.execute_batch(&trigger).unwrap();
    let changed_digest: Vec<u8> = connection
        .query_row(
            "SELECT plaintext_digest FROM provider_remote_response_bindings
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(changed_digest, vec![0x56; 32]);
    assert_eq!(
        trigger_sql(&connection, "provider_remote_response_bindings_immutable"),
        trigger
    );
    assert_reopen_rejected(&prepared);

    let prepared = pending("remote-v59-artifact-tamper", 0x95);
    let connection = prepared.fixture.database.connection();
    let trigger = trigger_sql(&connection, "provider_remote_terminal_artifacts_immutable");
    connection
        .execute_batch("DROP TRIGGER provider_remote_terminal_artifacts_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_remote_terminal_artifacts SET plaintext_digest=?1
             WHERE dispatch_attempt_id=?2",
            rusqlite::params![
                [0x57_u8; 32].as_slice(),
                prepared.attempt.as_bytes().as_slice()
            ],
        )
        .unwrap();
    assert_eq!(connection.changes(), 1);
    connection.execute_batch(&trigger).unwrap();
    let changed_digest: Vec<u8> = connection
        .query_row(
            "SELECT plaintext_digest FROM provider_remote_terminal_artifacts
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(changed_digest, vec![0x57; 32]);
    assert_eq!(
        trigger_sql(&connection, "provider_remote_terminal_artifacts_immutable"),
        trigger
    );
    assert_reopen_rejected(&prepared);
}
