use super::{read_stop, record_stop};
use rusqlite::{Connection, TransactionBehavior};

fn fixture() -> (Connection, [u8; 16], [u8; 16], [u8; 32], [u8; 16]) {
    let connection = Connection::open_in_memory().expect("memory sqlite");
    connection.execute_batch(
        "CREATE TABLE events(event_id BLOB PRIMARY KEY,aggregate_type INTEGER,aggregate_id BLOB,sequence INTEGER);
         CREATE TABLE x2_permission_stop(taskrun_id BLOB,attempt_id BLOB,binding_digest BLOB,
           stop_id BLOB,reason INTEGER,observed_version INTEGER,event_id BLOB,stopped_at INTEGER,
           PRIMARY KEY(taskrun_id,attempt_id));",
    ).expect("fixture schema");
    let taskrun = [1; 16];
    let attempt = [2; 16];
    let digest = [3; 32];
    let event = [4; 16];
    connection
        .execute(
            "INSERT INTO events VALUES(?1,1,?2,7)",
            rusqlite::params![event.as_slice(), taskrun.as_slice()],
        )
        .expect("taskrun event");
    (connection, taskrun, attempt, digest, event)
}

#[test]
fn stop_is_first_wins_and_keeps_exact_event_version() {
    let (mut connection, taskrun, attempt, digest, event) = fixture();
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    record_stop(&tx, &taskrun, &attempt, &digest, 2, 7, &event, 10).unwrap();
    record_stop(&tx, &taskrun, &attempt, &digest, 5, 7, &event, 11).unwrap();
    assert_eq!(
        read_stop(&tx, &taskrun, &attempt, &digest).unwrap(),
        Some(2)
    );
    tx.commit().unwrap();
}

#[test]
fn stop_rejects_event_from_a_different_stream_version() {
    let (mut connection, taskrun, attempt, digest, event) = fixture();
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(record_stop(&tx, &taskrun, &attempt, &digest, 2, 8, &event, 10).is_err());
}
