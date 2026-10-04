use super::support::Prepared;
use runne_application::ports::EventStore;

fn expected_node_bytes(prepared: &Prepared) -> [u8; 16] {
    *uuid::Uuid::parse_str(&prepared.fixture.claim_identity.node_id.0)
        .expect("fixture node ID is a UUID")
        .as_bytes()
}

pub(super) fn assert_active_occupation(prepared: &Prepared) {
    let (state, attempt_id, node_id, node_epoch, release_event_id) = occupation(prepared);
    assert_eq!(state, "active");
    assert_eq!(
        attempt_id.as_slice(),
        prepared
            .fixture
            .claim_identity
            .attempt_id
            .as_bytes()
            .as_slice()
    );
    assert_eq!(node_id.as_slice(), expected_node_bytes(prepared).as_slice());
    assert_eq!(
        node_epoch,
        i64::try_from(prepared.fixture.claim_identity.node_epoch).unwrap()
    );
    assert!(release_event_id.is_none());
}

pub(super) fn assert_released_occupation(prepared: &Prepared) {
    let (state, attempt_id, node_id, node_epoch, release_event) = occupation(prepared);
    assert_eq!(state, "released");
    assert_eq!(
        attempt_id.as_slice(),
        prepared
            .fixture
            .claim_identity
            .attempt_id
            .as_bytes()
            .as_slice()
    );
    assert_eq!(node_id.as_slice(), expected_node_bytes(prepared).as_slice());
    assert_eq!(
        node_epoch,
        i64::try_from(prepared.fixture.claim_identity.node_epoch).unwrap()
    );
    let taskrun = prepared
        .fixture
        .database
        .store
        .load_task_run(prepared.fixture.taskrun_id)
        .unwrap();
    let terminal = taskrun
        .events
        .iter()
        .find(|event| {
            matches!(
                event.payload(),
                runne_domain::task_run::TaskRunEvent::TaskRunCompleted { .. }
            )
        })
        .expect("successful terminal TaskRun event");
    let release_event = release_event.expect("released occupation event");
    assert_eq!(release_event.as_slice(), terminal.event_id().as_bytes());
    let receipt: (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT fence,attempt_id,node_id,terminal_event_id,node_epoch,terminal_version
             FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![
                prepared.fixture.taskrun_id.as_bytes().as_slice(),
                i64::try_from(prepared.fixture.claim_identity.fence.0).unwrap()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        receipt.0,
        i64::try_from(prepared.fixture.claim_identity.fence.0).unwrap()
    );
    assert_eq!(receipt.1, attempt_id);
    assert_eq!(receipt.2, node_id);
    assert_eq!(receipt.3, release_event);
    assert_eq!(receipt.4, node_epoch);
    assert_eq!(receipt.5, i64::try_from(terminal.sequence()).unwrap());
}

pub(super) fn occupation(prepared: &Prepared) -> (String, Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>) {
    prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT state,attempt_id,node_id,node_epoch,release_event_id
             FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![
                prepared.fixture.taskrun_id.as_bytes().as_slice(),
                i64::try_from(prepared.fixture.claim_identity.fence.0).unwrap()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap()
}
