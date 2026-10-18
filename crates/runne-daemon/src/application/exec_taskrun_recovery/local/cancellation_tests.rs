#[path = "cancellation_tests/branch_fixture.rs"]
mod branch_fixture;

use super::recover_cancelling;
use branch_fixture::{CancellationBranchFixture, fixture};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{EventStore, ExecutionNodeId};
use runne_application::service::TaskRunService;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::process_managed_area::{LinuxManagedArea, LinuxManagedAreaRoot};
use std::sync::{Arc, atomic::AtomicU64};
use std::time::{Duration, Instant};

use crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns;

fn guard() -> std::sync::Arc<dyn runne_application::prohibited_content::ProhibitedContentPort> {
    branch_fixture::guard()
}

fn recovery_candidate(
    fixture: &CancellationBranchFixture,
) -> runne_store::store::LocalCommandRecoveryCandidate {
    fixture
        .store
        .scan_local_command_recovery(None, 16)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.identity.taskrun_id == fixture.taskrun_id)
        .expect("durable cancellation candidate")
}

fn attempt_state(fixture: &CancellationBranchFixture) -> String {
    rusqlite::Connection::open(&fixture.db_path)
        .unwrap()
        .query_row(
            "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap()
}

fn scalar(fixture: &CancellationBranchFixture, sql: &str) -> i64 {
    rusqlite::Connection::open(&fixture.db_path)
        .unwrap()
        .query_row(sql, [fixture.taskrun_id.as_bytes()], |row| row.get(0))
        .unwrap()
}

fn worker_for(fixture: &CancellationBranchFixture) -> DaemonAutomaticTaskRuns {
    let authority = runne_application::ports::RuntimeAuthorityId(fixture.node.clone());
    let text: Arc<dyn ConversationTextCommandService> = Arc::new(ConversationTextService::new(
        fixture.store.clone(),
        fixture.store.clone(),
        authority.clone(),
        guard(),
    ));
    DaemonAutomaticTaskRuns::new(
        fixture.store.clone(),
        Arc::new(TaskRunService::new(
            fixture.store.clone(),
            fixture.store.clone(),
            fixture.store.clone(),
            authority,
        )),
        text,
        None,
        ExecutionNodeId(fixture.node.clone()),
        fixture.worker_epoch,
        Arc::new(AtomicU64::new(fixture.worker_epoch)),
    )
}

/// Attaches a live, observable child to the fixture area.
fn attach_live_child(area: &LinuxManagedArea) -> std::process::Child {
    let child = std::process::Command::new("bash")
        .arg("-c")
        .arg("while :; do sleep 0.2; done")
        .spawn()
        .expect("live fixture child");
    let pid = child.id();
    // The attach gate requires the child to be observably stopped, which is
    // asynchronous after SIGSTOP; retry instead of racing it, and never leak a
    // stopped orphan if the gate still refuses the child.
    let attach_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        unsafe {
            assert_eq!(libc::kill(pid as i32, libc::SIGSTOP), 0);
        }
        match area.attach_gated_process(pid) {
            Ok(()) => break,
            Err(runne_platform::process_managed_area::ManagedAreaError::Unverified)
                if Instant::now() < attach_deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                unsafe {
                    let _ = libc::kill(pid as i32, libc::SIGKILL);
                }
                let _ = child.wait_with_output();
                panic!("attach gated child: {error:?}");
            }
        }
    }
    unsafe {
        assert_eq!(libc::kill(pid as i32, libc::SIGCONT), 0);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !area.is_populated().unwrap() {
        assert!(
            Instant::now() < deadline,
            "fixture child never entered the area"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

fn reopened_area(fixture: &CancellationBranchFixture) -> LinuxManagedArea {
    let bytes = fixture.area.identity().to_bytes();
    let identity =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&bytes).unwrap();
    let fields = identity.to_bytes();
    LinuxManagedAreaRoot::open_current_cgroup()
        .unwrap()
        .reopen_area(
            identity,
            runne_platform::process_managed_area::ManagedAreaBinding::new(
                fields[52..68].try_into().unwrap(),
                fields[68..84].try_into().unwrap(),
                fields[84..100].try_into().unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn missing_evidence_stops_the_live_child_and_settles_unconfirmed() {
    let fixture = fixture("cancel-branch-missing-running", "running", None);
    let worker = worker_for(&fixture);
    let mut child = attach_live_child(&fixture.area);
    let stream = fixture.store.load_task_run(fixture.taskrun_id).unwrap();
    let candidate = recovery_candidate(&fixture);
    assert_eq!(
        recover_cancelling(&worker, &candidate, stream, reopened_area(&fixture)),
        Ok(())
    );
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "the live child must be terminated before recovery settles"
    );
    assert!(!fixture.area.is_populated().unwrap());
    assert_eq!(attempt_state(&fixture), "stop_unconfirmed");
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1"
        ),
        0,
        "no fabricated cancellation settlement"
    );
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1"
        ),
        0,
        "no fabricated permission stop reason"
    );
    let run = fixture.store.load_task_run(fixture.taskrun_id).unwrap();
    assert_eq!(
        TaskRun::replay(&run.events).unwrap().state(),
        TaskRunState::Cancelling
    );
}

#[tokio::test(flavor = "current_thread")]
async fn missing_evidence_with_factual_exit_is_a_categorized_conflict() {
    let fixture = fixture("cancel-branch-missing-completed", "completed", Some(137));
    let worker = worker_for(&fixture);
    let stream = fixture.store.load_task_run(fixture.taskrun_id).unwrap();
    let candidate = recovery_candidate(&fixture);
    assert_eq!(
        recover_cancelling(&worker, &candidate, stream, reopened_area(&fixture)),
        Err("complete_stop_conflict")
    );
    assert_eq!(
        attempt_state(&fixture),
        "completed",
        "mark_unconfirmed is never called for a factual terminal attempt"
    );
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1"
        ),
        0
    );
}
