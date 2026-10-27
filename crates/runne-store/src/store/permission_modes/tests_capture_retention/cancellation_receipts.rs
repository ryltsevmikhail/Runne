//! Full typed rows, total TaskRun cardinalities; SELECT only.
use super::{
    metadata::Area,
    observations::{self, one},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
pub(super) type Stop = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, i64);
pub(super) type Occupation = (
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
pub(super) type Terminal = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rows {
    pub stop: Stop,
    pub occupation: Occupation,
    pub terminal: Option<Terminal>,
}
pub(super) fn validate_stop(s: &Stop, a: &Area, head: &[u8], version: u64) {
    let id = a.identity();
    assert_eq!(s.0, id.taskrun_id.as_bytes());
    assert_eq!(s.1, id.attempt_id.as_bytes());
    assert_eq!(s.2, a.capture.binding_digest);
    let stop: [u8; 16] = s.3.as_slice().try_into().unwrap();
    runne_domain::id::validate_uuid_v7_bytes(&stop).unwrap();
    assert_eq!(s.4, 1);
    assert_eq!(s.5, i64::try_from(version).unwrap());
    assert_eq!(s.6, head);
    assert!(s.7 > 0);
}
pub(super) fn validate_occupation(o: &Occupation, a: &Area, head: Option<&[u8]>) {
    let id = a.identity();
    assert_eq!(o.0, id.taskrun_id.as_bytes());
    assert_eq!(o.1, i64::try_from(id.fence.0).unwrap());
    assert_eq!(o.2, id.attempt_id.as_bytes());
    assert_eq!(o.3, a.authority);
    assert_eq!(o.4, i64::try_from(a.epoch).unwrap());
    assert!(o.5 > 0);
    assert_eq!(o.6, if head.is_some() { "released" } else { "active" });
    assert_eq!(o.7, "absent");
    assert_eq!(o.8.as_deref(), head);
}
pub(super) fn observe(
    c: &Connection,
    a: &Area,
    cancel_head: &[u8],
    cancel_version: u64,
    terminal: Option<(&[u8], u64)>,
) -> Rows {
    let stop: Stop = one(
        c,
        "SELECT taskrun_id,attempt_id,binding_digest,stop_id,reason,
        observed_version,event_id,stopped_at FROM x2_permission_stop WHERE taskrun_id=?1",
        a,
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        },
    );
    validate_stop(&stop, a, cancel_head, cancel_version);
    let occupation: Occupation=one(c,"SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,
        lease_expires_at_ms,state,dispatch_intent,release_event_id FROM taskrun_assignment_occupations
        WHERE taskrun_id=?1",a,|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,
            r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)));
    validate_occupation(&occupation, a, terminal.map(|(head, _)| head));
    observations::count(
        c,
        "taskrun_terminal_settlement_receipts",
        a,
        if terminal.is_some() { 1 } else { 0 },
    );
    let terminal=terminal.map(|(head,version)| {
        let value: Terminal=one(c,"SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,
            terminal_event_id,terminal_version FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1",
            a,|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)));
        assert_eq!(value,(occupation.0.clone(),occupation.1,occupation.2.clone(),occupation.3.clone(),
            occupation.4,head.to_vec(),i64::try_from(version).unwrap())); value
    });
    observations::no_factual_terminal_or_provider(c, a);
    observations::count(c, "taskrun_local_command_stop_receipts", a, 0);
    Rows {
        stop,
        occupation,
        terminal,
    }
}
