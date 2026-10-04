use super::verify_empty_local_recovery_scan;
use runne_application::ports::{
    EventStoreError, ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence,
};
use runne_domain::id::{AttemptId, TaskRunId};
use runne_store::store::{LocalCommandAttemptState, LocalCommandRecoveryCandidate};

fn candidate() -> LocalCommandRecoveryCandidate {
    LocalCommandRecoveryCandidate {
        identity: TaskRunAssignmentIdentity {
            taskrun_id: TaskRunId::from_bytes([1; 16]),
            attempt_id: AttemptId::from_bytes([2; 16]),
            node_id: ExecutionNodeId("00000000-0000-0000-0000-000000000003".into()),
            node_epoch: 1,
            fence: TaskRunFence(1),
        },
        area_identity: vec![0; 100],
        state: LocalCommandAttemptState::Running,
        exit_code: None,
    }
}

#[test]
fn provider_only_fixture_accepts_an_empty_local_scan() {
    let result = verify_empty_local_recovery_scan(|_, _| Ok(Vec::new()));
    assert_eq!(result, Ok(()));
}

#[test]
fn provider_only_fixture_rejects_retained_local_attempt() {
    let result = verify_empty_local_recovery_scan(|_, _| Ok(vec![candidate()]));
    assert_eq!(result, Err("provider_fixture_local_attempts_present"));
}

#[test]
fn provider_only_fixture_propagates_scan_unavailability() {
    let result = verify_empty_local_recovery_scan(|_, _| Err(EventStoreError::Unavailable));
    assert_eq!(result, Err("provider_fixture_local_scan"));
}
