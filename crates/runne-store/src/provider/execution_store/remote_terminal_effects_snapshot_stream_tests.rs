use super::classify_stream_output;
use runne_application::provider::{
    ProviderExecutionError, ProviderRemoteLocalDisposition as Local,
};
use rusqlite::{Connection, params};

fn fixture() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    // Schema-only projection inputs, not an authorized runtime or effect fixture.
    connection
        .execute_batch(
            "CREATE TABLE provider_terminal_outbox(
          dispatch_attempt_id BLOB, outbox_id BLOB, plaintext_digest BLOB,
          state INTEGER, receipt_digest BLOB, applied_at INTEGER);
         CREATE TABLE d2_tool_loop_completions(
          command_id BLOB, terminal_attempt_id BLOB, terminal_outbox_id BLOB,
          completed_receipt_digest BLOB, assistant_text_digest BLOB);
         CREATE TABLE command_receipts(command_id BLOB,command_outcome BLOB);",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_terminal_outbox VALUES(?1,?2,?3,2,?4,1)",
            params![[1u8; 16], [2u8; 16], [3u8; 32], [4u8; 32]],
        )
        .unwrap();
    connection
}

#[test]
fn acknowledged_without_canonical_completion_never_claims_publication() {
    let mut connection = fixture();
    let tx = connection.transaction().unwrap();
    // Cancellation/audit ACKs use this same state2 shape, without a completion.
    assert_eq!(
        classify_stream_output(&tx, &[1; 16], &[3; 32]).unwrap(),
        Local::Unknown
    );
}

#[test]
fn pending_and_wrong_output_remain_distinct() {
    let mut connection = fixture();
    connection
        .execute(
            "UPDATE provider_terminal_outbox SET state=1,receipt_digest=NULL,applied_at=NULL",
            [],
        )
        .unwrap();
    let tx = connection.transaction().unwrap();
    assert_eq!(
        classify_stream_output(&tx, &[1; 16], &[3; 32]).unwrap(),
        Local::Pending
    );
    assert!(matches!(
        classify_stream_output(&tx, &[1; 16], &[9; 32]),
        Err(ProviderExecutionError::JournalCorrupt)
    ));
}

#[test]
fn forged_completion_link_does_not_replace_canonical_receipt_validation() {
    let mut connection = fixture();
    connection
        .execute(
            "INSERT INTO d2_tool_loop_completions VALUES(?1,?2,?3,?4,?5)",
            params![[5u8; 16], [1u8; 16], [2u8; 16], [4u8; 32], [3u8; 32]],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO command_receipts VALUES(?1,?2)",
            params![[5u8; 16], vec![1u8, 2, 3]],
        )
        .unwrap();
    let tx = connection.transaction().unwrap();
    assert!(matches!(
        classify_stream_output(&tx, &[1; 16], &[3; 32]),
        Err(ProviderExecutionError::JournalCorrupt)
    ));
}

#[test]
fn other_dispatch_completion_cannot_prove_this_output() {
    let mut connection = fixture();
    connection
        .execute(
            "INSERT INTO d2_tool_loop_completions VALUES(?1,?2,?3,?4,?5)",
            params![[5u8; 16], [9u8; 16], [2u8; 16], [4u8; 32], [3u8; 32]],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO command_receipts VALUES(?1,?2)",
            params![[5u8; 16], vec![1u8, 2, 3]],
        )
        .unwrap();
    let tx = connection.transaction().unwrap();
    assert_eq!(
        classify_stream_output(&tx, &[1; 16], &[3; 32]).unwrap(),
        Local::Unknown
    );
}
