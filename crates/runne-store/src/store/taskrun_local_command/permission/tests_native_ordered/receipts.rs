//! Fresh managed Reader observations, not controller/writer restart evidence.
use super::super::fixture::Fixture;
use crate::schema::{ConnectionMode, open_managed_connection};
use runne_application::{permission_modes::LocalCommandPermissionBindingV1, ports::EventStore};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use rusqlite::params;

pub(super) fn spent(f: &Fixture, b: &LocalCommandPermissionBindingV1) -> i64 {
    let reader = open_managed_connection(
        &f.root.path().join("runtime/daemon/store.sqlite"),
        ConnectionMode::Reader,
    )
    .unwrap();
    reader
        .query_row(
            "SELECT count(*) FROM x2_permission_spent WHERE taskrun_id=?1 AND attempt_id=?2",
            params![
                b.assignment().taskrun_id.as_bytes(),
                b.assignment().attempt_id.as_bytes()
            ],
            |r| r.get(0),
        )
        .unwrap()
}

pub(super) fn stop_anchor(f: &Fixture, b: &LocalCommandPermissionBindingV1, reason: i64) {
    let reader = open_managed_connection(
        &f.root.path().join("runtime/daemon/store.sqlite"),
        ConnectionMode::Reader,
    )
    .unwrap();
    let capture = f
        .store
        .load_local_command_permission_capture(b.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    let matched: i64 = reader.query_row(
        "SELECT count(*) FROM x2_permission_stop s JOIN events e ON e.event_id=s.event_id
         WHERE s.taskrun_id=?1 AND s.attempt_id=?2 AND s.binding_digest=?3 AND s.reason=?4
           AND e.aggregate_type=1 AND e.aggregate_id=s.taskrun_id AND e.sequence=s.observed_version
           AND s.observed_version=(SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=s.taskrun_id)",
        params![b.assignment().taskrun_id.as_bytes(),b.assignment().attempt_id.as_bytes(),capture.binding_digest,reason], |r| r.get(0)).unwrap();
    assert_eq!(matched, 1);
}

pub(super) fn settled(
    f: &Fixture,
    b: &LocalCommandPermissionBindingV1,
    area: &[u8; 100],
    released: bool,
) {
    let id = b.assignment();
    let loaded = f.store.load_task_run(id.taskrun_id).unwrap();
    let task = TaskRun::replay(&loaded.events).unwrap();
    let terminal = loaded.events.last().unwrap();
    if released {
        assert_eq!(task.state(), TaskRunState::Failed);
        assert!(
            matches!(terminal.payload(), TaskRunEvent::TaskRunFailed { reason } if reason=="local_command_policy_stopped_v1")
        );
    } else {
        assert_eq!(task.state(), TaskRunState::Cancelled);
        assert!(matches!(
            terminal.payload(),
            TaskRunEvent::CancellationCompleted
        ));
        assert!(matches!(
            loaded.events[loaded.events.len() - 2].payload(),
            TaskRunEvent::CancellationRequested
        ));
    }
    let reader = open_managed_connection(
        &f.root.path().join("runtime/daemon/store.sqlite"),
        ConnectionMode::Reader,
    )
    .unwrap();
    let node = uuid::Uuid::parse_str(&id.node_id.0).unwrap();
    let (state, exit, saved_area): (String, Option<i32>, Vec<u8>) = reader
        .query_row(
            "SELECT state,exit_code,managed_area_identity FROM taskrun_local_command_attempts
         WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND node_id=?4 AND node_epoch=?5",
            params![
                id.taskrun_id.as_bytes(),
                id.attempt_id.as_bytes(),
                id.fence.0 as i64,
                node.as_bytes(),
                id.node_epoch as i64
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(state, "cancelled");
    assert_eq!(exit, released.then_some(0));
    assert_eq!(saved_area, area);
    let count: i64 = reader.query_row(
        "SELECT count(*) FROM taskrun_terminal_settlement_receipts t
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=t.taskrun_id AND o.fence=t.fence
         JOIN events e ON e.event_id=t.terminal_event_id
         JOIN aggregate_streams a ON a.aggregate_type=1 AND a.aggregate_id=t.taskrun_id
         JOIN aggregate_state_snapshots p ON p.aggregate_type=1 AND p.aggregate_id=t.taskrun_id
         JOIN x2_permission_stop s ON s.taskrun_id=t.taskrun_id AND s.attempt_id=t.attempt_id
         JOIN events se ON se.event_id=s.event_id
         WHERE t.taskrun_id=?1 AND t.attempt_id=?2 AND t.fence=?3 AND t.node_id=?4 AND t.node_epoch=?5
          AND t.terminal_event_id=?6 AND t.terminal_version=?7
          AND o.attempt_id=t.attempt_id AND o.node_id=t.node_id AND o.node_epoch=t.node_epoch
          AND o.state='released' AND o.release_event_id=t.terminal_event_id
          AND e.aggregate_type=1 AND e.aggregate_id=t.taskrun_id AND e.sequence=t.terminal_version
          AND a.current_version=t.terminal_version AND a.last_event_id=t.terminal_event_id
          AND p.aggregate_version=a.current_version AND p.event_sequence=a.current_version AND p.head_event_id=a.last_event_id
          AND s.reason=?8 AND s.observed_version=t.terminal_version-1
          AND se.aggregate_type=1 AND se.aggregate_id=t.taskrun_id AND se.sequence=s.observed_version",
        params![id.taskrun_id.as_bytes(),id.attempt_id.as_bytes(),id.fence.0 as i64,node.as_bytes(),id.node_epoch as i64,
            terminal.event_id().as_bytes(),loaded.current_version as i64,if released {3i64} else {1i64}], |r|r.get(0)).unwrap();
    assert_eq!(count, 1);
    assert_eq!(spent(f, b), i64::from(released));
    let terminals: i64 = reader
        .query_row(
            "SELECT count(*) FROM x2_permission_terminal WHERE taskrun_id=?1 AND attempt_id=?2",
            params![id.taskrun_id.as_bytes(), id.attempt_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(terminals, i64::from(released));
    if released {
        let capture = f
            .store
            .load_local_command_permission_capture(id.taskrun_id)
            .unwrap()
            .unwrap();
        let exact: i64 = reader.query_row(
            "SELECT count(*) FROM x2_permission_terminal t JOIN x2_permission_spent s USING(taskrun_id,attempt_id)
             WHERE t.taskrun_id=?1 AND t.attempt_id=?2 AND t.binding_digest=?3 AND t.binding_digest=s.binding_digest
              AND s.invocation_id=?4 AND s.area_identity=?5 AND s.owner_id=?6 AND s.owner_generation=?7
              AND t.fence=?8 AND t.event_id=?9 AND t.terminal_version=?10
              AND t.exit_kind=1 AND t.exit_code=0 AND t.signal IS NULL AND t.area_empty=1
              AND t.stdout=X'' AND t.stderr=X'' AND t.stdout_observed=0 AND t.stderr_observed=0
              AND t.stdout_eof=1 AND t.stderr_eof=1 AND t.stdout_truncated=0 AND t.stderr_truncated=0",
            params![id.taskrun_id.as_bytes(),id.attempt_id.as_bytes(),capture.binding_digest,b.invocation_id().as_bytes(),area,
                capture.native_owner_id,capture.native_owner_generation.to_be_bytes(),id.fence.0 as i64,
                terminal.event_id().as_bytes(),loaded.current_version as i64],|r|r.get(0)).unwrap();
        assert_eq!(exact, 1);
    }
}
