//! SELECT-only observations through independently admitted fresh readers.
use super::metadata::{Area, Capture};
use crate::schema::{self, ConnectionMode, ManagedConnection};
use crate::store::{LocalCommandAttemptState, StoreTransaction};
use runne_application::ports::EventStore;
use runne_domain::task_run::{TaskRun, TaskRunState};
use rusqlite::{Connection, Row};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(super) fn reader(root: &Path, area: &Area) -> ManagedConnection {
    reopen(root, area, ConnectionMode::Reader)
}
pub(super) fn reopen(root: &Path, area: &Area, mode: ConnectionMode) -> ManagedConnection {
    let db = area.daemon(root).join("store.sqlite");
    super::paths::regular(&db);
    let lineage = area.lineage.parse().unwrap();
    schema::reopen_managed_connection_validated(&db, mode, |c| {
        if schema::read_authority_id(c)? != Some(area.authority)
            || schema::read_event_log_lineage_id(c)? != Some(lineage)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    })
    .unwrap()
}

pub(super) fn one<T>(
    c: &Connection,
    sql: &str,
    area: &Area,
    f: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> T {
    let id = area.identity();
    let mut statement = c.prepare(sql).unwrap();
    let mut rows = statement
        .query_map([id.taskrun_id.as_bytes()], f)
        .unwrap()
        .collect::<rusqlite::Result<Vec<T>>>()
        .unwrap();
    assert_eq!(rows.len(), 1, "exact total assignment cardinality");
    rows.remove(0)
}
pub(super) fn count(c: &Connection, table: &str, area: &Area, expected: i64) {
    assert!(matches!(
        table,
        "x2_permission_terminal"
            | "taskrun_terminal_settlement_receipts"
            | "taskrun_local_command_stop_receipts"
            | "taskrun_provider_bindings"
            | "taskrun_dispatch_intents"
    ));
    let sql = format!("SELECT count(*) FROM {table} WHERE taskrun_id=?1");
    let id = area.identity();
    let n: i64 = c
        .query_row(&sql, [id.taskrun_id.as_bytes()], |r| r.get(0))
        .unwrap();
    assert_eq!(n, expected, "{table}");
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Spent {
    pub task: Vec<u8>,
    pub attempt: Vec<u8>,
    pub binding: Vec<u8>,
    pub invocation: Vec<u8>,
    pub area: Vec<u8>,
    pub owner: Vec<u8>,
    pub generation: Vec<u8>,
    pub burn_id: Vec<u8>,
    pub burned_at: i64,
}
impl Spent {
    pub fn assert_original(&self, a: &Area) {
        let id = a.identity();
        assert_eq!(self.task, id.taskrun_id.as_bytes());
        assert_eq!(self.attempt, id.attempt_id.as_bytes());
        assert_eq!(self.binding, a.capture.binding_digest);
        let invocation: runne_domain::id::InvocationId = a.capture.invocation.parse().unwrap();
        assert_eq!(self.invocation, invocation.as_bytes());
        assert_eq!(self.area, a.area);
        assert_eq!(self.owner, a.capture.owner);
        assert_eq!(self.generation, a.capture.generation.to_be_bytes());
        let burn: [u8; 16] = self.burn_id.as_slice().try_into().unwrap();
        runne_domain::id::validate_uuid_v7_bytes(&burn).unwrap();
        assert!(self.burned_at > 0);
    }
}
pub(super) fn spent(c: &Connection, area: &Area) -> Spent {
    let value = one(
        c,
        "SELECT taskrun_id,attempt_id,binding_digest,invocation_id,area_identity,
        owner_id,owner_generation,burn_id,burned_at FROM x2_permission_spent WHERE taskrun_id=?1",
        area,
        |r| {
            Ok(Spent {
                task: r.get(0)?,
                attempt: r.get(1)?,
                binding: r.get(2)?,
                invocation: r.get(3)?,
                area: r.get(4)?,
                owner: r.get(5)?,
                generation: r.get(6)?,
                burn_id: r.get(7)?,
                burned_at: r.get(8)?,
            })
        },
    );
    value.assert_original(area);
    value
}

// All identity, state, area, digest and nullable durable exit fields are retained.
type Attempt = (
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    String,
    Option<i32>,
    Vec<u8>,
);
pub(super) fn attempt(c: &Connection, area: &Area, state: &str) -> Attempt {
    let value: Attempt = one(
        c,
        "SELECT taskrun_id,attempt_id,fence,node_id,node_epoch,
        managed_area_identity,state,exit_code,command_digest FROM taskrun_local_command_attempts
        WHERE taskrun_id=?1",
        area,
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
                r.get(8)?,
            ))
        },
    );
    let id = area.identity();
    assert_eq!(value.0, id.taskrun_id.as_bytes());
    assert_eq!(value.1, id.attempt_id.as_bytes());
    assert_eq!(value.2, i64::try_from(id.fence.0).unwrap());
    assert_eq!(value.3, area.authority);
    assert_eq!(value.4, i64::try_from(area.epoch).unwrap());
    assert_eq!(value.5, area.area);
    assert_eq!(value.6, state);
    assert_eq!(value.7, None);
    assert_eq!(value.8, area.command_digest);
    value
}
pub(super) fn capture(store: &StoreTransaction, area: &Area, state: LocalCommandAttemptState) {
    let value = store
        .load_local_command_permission_capture(area.identity().taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(Capture::of(&value), area.capture);
    assert_eq!(value.state, state);
}
pub(super) fn stream(
    store: &StoreTransaction,
    area: &Area,
    state: TaskRunState,
) -> (u64, Vec<Vec<u8>>) {
    let value = store.load_task_run(area.identity().taskrun_id).unwrap();
    assert_eq!(TaskRun::replay(&value.events).unwrap().state(), state);
    let ids: Vec<Vec<u8>> = value
        .events
        .iter()
        .map(|e| e.event_id().as_bytes().to_vec())
        .collect();
    assert_eq!(
        value.last_event_id.unwrap().as_bytes(),
        ids.last().unwrap().as_slice()
    );
    (value.current_version, ids)
}
pub(super) fn no_factual_terminal_or_provider(c: &Connection, area: &Area) {
    for table in [
        "x2_permission_terminal",
        "taskrun_provider_bindings",
        "taskrun_dispatch_intents",
    ] {
        count(c, table, area, 0);
    }
}
