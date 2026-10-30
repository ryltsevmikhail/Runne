#[test]
fn remote_effect_dispatch_query_retains_coding_rounds_and_overflow_sentinel() {
    let mut connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE provider_remote_request_intents(
        dispatch_attempt_id BLOB, taskrun_id BLOB, taskrun_attempt_id BLOB);",
        )
        .unwrap();
    let task = TaskRunId::from_bytes([1; 16]);
    let attempt = AttemptId::from_bytes([2; 16]);
    for index in 0_u8..35 {
        connection
            .execute(
                "INSERT INTO provider_remote_request_intents VALUES(?1,?2,?3)",
                params![
                    [index; 16].as_slice(),
                    task.as_bytes().as_slice(),
                    attempt.as_bytes().as_slice()
                ],
            )
            .unwrap();
    }
    let transaction = connection.transaction().unwrap();
    let ids = remote_effect_dispatch_ids(&transaction, task, attempt).unwrap();
    assert_eq!(ids.len(), 34, "33 coding rounds plus one overflow sentinel");
    assert_eq!(ids[32], [32; 16]);
    assert_eq!(ids[33], [33; 16]);
}
