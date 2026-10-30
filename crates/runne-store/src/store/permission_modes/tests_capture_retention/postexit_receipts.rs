use super::{
    metadata::Area,
    observations::{self, one},
};
use rusqlite::Connection;

// Complete rows: seven terminal columns, twelve stop columns, nine occupation columns.
type Terminal = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64);
type Stop = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    i64,
);
type Occupation = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    String,
    String,
    Option<Vec<u8>>,
);
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Receipts {
    terminal: Terminal,
    stop: Stop,
    occupation: Occupation,
}
pub(super) fn observe(c: &Connection, a: &Area, epoch: u64, head: &[u8], version: u64) -> Receipts {
    let terminal: Terminal = one(c, "SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,
        terminal_event_id,terminal_version FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1", a,
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)));
    let stop: Stop = one(c, "SELECT taskrun_id,fence,attempt_id,historic_node_id,historic_node_epoch,
        proof_node_id,proof_node_epoch,managed_area_identity,command_digest,stop_kind,terminal_event_id,
        terminal_version FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1", a,
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,
            r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?)));
    let occupation: Occupation = one(c, "SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,
        lease_expires_at_ms,state,dispatch_intent,release_event_id FROM taskrun_assignment_occupations
        WHERE taskrun_id=?1", a,
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)));
    let id = a.identity();
    let fence = i64::try_from(id.fence.0).unwrap();
    let historic = i64::try_from(a.epoch).unwrap();
    let version = i64::try_from(version).unwrap();
    assert_eq!(
        terminal,
        (
            id.taskrun_id.as_bytes().to_vec(),
            fence,
            id.attempt_id.as_bytes().to_vec(),
            a.authority.to_vec(),
            historic,
            head.to_vec(),
            version
        )
    );
    assert!(epoch > a.epoch);
    assert_eq!(
        stop,
        (
            terminal.0.clone(),
            fence,
            terminal.2.clone(),
            a.authority.to_vec(),
            historic,
            a.authority.to_vec(),
            i64::try_from(epoch).unwrap(),
            a.area.clone(),
            a.command_digest.to_vec(),
            "outcome_unknown".into(),
            head.to_vec(),
            version
        )
    );
    assert_eq!(occupation.0, terminal.0);
    assert_eq!(occupation.1, fence);
    assert_eq!(occupation.2, terminal.2);
    assert_eq!(occupation.3, a.authority);
    assert_eq!(occupation.4, historic);
    assert!(occupation.5 > 0);
    assert_eq!(occupation.6, "released");
    assert_eq!(occupation.7, "absent");
    assert_eq!(occupation.8, Some(head.to_vec()));
    // Cardinality is total for the original TaskRun, not only a matching EXISTS.
    observations::count(c, "taskrun_terminal_settlement_receipts", a, 1);
    observations::count(c, "taskrun_local_command_stop_receipts", a, 1);
    observations::no_factual_terminal_or_provider(c, a);
    Receipts {
        terminal,
        stop,
        occupation,
    }
}
