use super::*;

#[test]
fn claimed_safe_stop_requires_exact_unlaunched_assignment_and_no_effect_evidence() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE taskrun_tool_invocations (
                taskrun_id BLOB, attempt_id BLOB, cycle_id BLOB, proposal_index INTEGER,
                semantic_digest BLOB, state TEXT, result_truncated INTEGER,
                local_stop_state INTEGER, managed_area_identity BLOB,
                empty_proof_identity BLOB, release_started INTEGER,
                claim_fence INTEGER, claim_node_id TEXT, claim_node_epoch INTEGER,
                result_digest BLOB, receipt_nonce BLOB
            );",
        )
        .unwrap();
    let taskrun_id = runne_domain::id::TaskRunId::from_bytes([1; 16]);
    let attempt_id = runne_domain::id::AttemptId::from_bytes([2; 16]);
    let cycle_id = runne_domain::id::CycleId::from_bytes([3; 16]);
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id,
        node_id: runne_application::ports::ExecutionNodeId(
            "11111111-1111-1111-1111-111111111111".into(),
        ),
        node_epoch: 4,
        fence: runne_application::ports::TaskRunFence(5),
    };
    let insert = |fence: i64, release: i64, area: Option<&[u8]>| {
        connection.execute(
                "INSERT INTO taskrun_tool_invocations (
                    taskrun_id,attempt_id,cycle_id,proposal_index,semantic_digest,state,
                    result_truncated,local_stop_state,managed_area_identity,empty_proof_identity,
                    release_started,claim_fence,claim_node_id,claim_node_epoch,result_digest,receipt_nonce
                 ) VALUES (?1,?2,?3,0,?4,'claimed',NULL,0,?5,NULL,?6,?7,?8,?9,NULL,NULL)",
                rusqlite::params![
                    taskrun_id.as_bytes(),
                    attempt_id.as_bytes(),
                    cycle_id.as_bytes(),
                    [9_u8; 32].as_slice(),
                    area,
                    release,
                    fence,
                    assignment.node_id.0,
                    assignment.node_epoch as i64,
                ],
            ).unwrap();
    };
    insert(5, 0, None);
    let tx = connection.unchecked_transaction().unwrap();
    assert!(
        verify_safe_tool_stop(&tx, taskrun_id, attempt_id, cycle_id, &assignment, false,).is_ok()
    );
    tx.rollback().unwrap();

    connection
        .execute("DELETE FROM taskrun_tool_invocations", [])
        .unwrap();
    insert(6, 0, None);
    let tx = connection.unchecked_transaction().unwrap();
    assert!(
        verify_safe_tool_stop(&tx, taskrun_id, attempt_id, cycle_id, &assignment, false,).is_err(),
        "a Claimed row bound to another fence cannot be safe-stopped"
    );
    tx.rollback().unwrap();

    connection
        .execute("DELETE FROM taskrun_tool_invocations", [])
        .unwrap();
    insert(5, 1, None);
    let tx = connection.unchecked_transaction().unwrap();
    assert!(
        verify_safe_tool_stop(&tx, taskrun_id, attempt_id, cycle_id, &assignment, false,).is_err(),
        "a Claimed row with durable release intent cannot be safe-stopped"
    );
}
