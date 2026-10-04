use super::super::t1_taskrun_support::LocalTaskRunContext;
use std::time::{Duration, Instant};

pub(super) fn assert_local_settled(
    context: &LocalTaskRunContext<'_>,
    task_id: runne_runtime_client::CanonicalId,
    state: &str,
    exit: Option<i32>,
) {
    let bytes = uuid::Uuid::parse_str(&task_id.to_string())
        .unwrap()
        .into_bytes();
    let connection = rusqlite::Connection::open(context.database).unwrap();
    let (actual_state, actual_exit, area): (String, Option<i32>, Vec<u8>) = connection
        .query_row(
            "SELECT state,exit_code,managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(actual_state, state);
    assert_eq!(actual_exit, exit);
    let identity =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&area).unwrap();
    let root =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    wait_for_daemon_cleanup(&root, &identity);
    let (occupation, release, receipt): (String, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT o.state,o.release_event_id,r.terminal_event_id
             FROM taskrun_assignment_occupations o
             JOIN taskrun_terminal_settlement_receipts r USING(taskrun_id,fence)
             WHERE o.taskrun_id=?1",
            [bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(occupation, "released");
    assert_eq!(release, receipt);
}

fn wait_for_daemon_cleanup(
    root: &runne_platform::process_managed_area::LinuxManagedAreaRoot,
    identity: &runne_platform::process_managed_area::ManagedAreaIdentity,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if root.area_is_absent(identity).unwrap() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not remove settled area"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
