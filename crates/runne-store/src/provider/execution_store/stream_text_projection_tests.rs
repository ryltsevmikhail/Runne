use super::{assistant_matches, receipt_digest};
use crate::codec::{ConversationEventCodec, StoreCodec as _};
use runne_application::ports::{TextGenerationPhase, TextGenerationReceipt};
use runne_domain::{conversation::ConversationEvent, id::*, message::MessageText};
use rusqlite::{Connection, params};
use sha2::{Digest as _, Sha256};

#[test]
fn canonical_legacy_assistant_event_proves_only_exact_output_and_command() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE events(aggregate_type INTEGER,aggregate_id BLOB,sequence INTEGER,command_id BLOB,payload BLOB)").unwrap();
    let receipt = TextGenerationReceipt {
        phase: TextGenerationPhase::Completed,
        conversation_id: ConversationId::from_bytes(uuid(1)),
        workspace_id: WorkspaceId::from_bytes(uuid(2)),
        taskrun_id: TaskRunId::from_bytes(uuid(3)),
        attempt_id: AttemptId::from_bytes(uuid(4)),
        user_message_id: MessageId::from_bytes(uuid(5)),
        assistant_message_id: MessageId::from_bytes(uuid(6)),
        conversation_version: 3,
        taskrun_version: 5,
    };
    let command = CommandId::from_bytes(uuid(7));
    let event = ConversationEvent::AssistantMessageAppended {
        message_id: receipt.assistant_message_id,
        taskrun_id: receipt.taskrun_id,
        attempt_id: receipt.attempt_id,
        text: MessageText::new("retained legacy output").unwrap(),
    };
    let bytes = ConversationEventCodec.encode(&event).unwrap();
    conn.execute(
        "INSERT INTO events VALUES(2,?1,3,?2,?3)",
        params![
            receipt.conversation_id.as_bytes(),
            command.as_bytes(),
            bytes
        ],
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    let output: [u8; 32] = Sha256::digest(b"retained legacy output").into();
    assert!(assistant_matches(&tx, command, &receipt, &output).unwrap());
    assert!(!assistant_matches(&tx, CommandId::from_bytes(uuid(8)), &receipt, &output).unwrap());
    assert!(!assistant_matches(&tx, command, &receipt, &[9; 32]).unwrap());
    let mut wrong = receipt.clone();
    wrong.attempt_id = AttemptId::from_bytes(uuid(10));
    assert!(!assistant_matches(&tx, command, &wrong, &output).unwrap());
    assert_ne!(
        receipt_digest(&uuid(11), &[12; 32], &receipt),
        receipt_digest(&uuid(11), &[12; 32], &wrong)
    );
    assert_ne!(
        receipt_digest(&uuid(11), &[12; 32], &receipt),
        receipt_digest(&uuid(13), &[12; 32], &receipt)
    );
}

fn uuid(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes
}
