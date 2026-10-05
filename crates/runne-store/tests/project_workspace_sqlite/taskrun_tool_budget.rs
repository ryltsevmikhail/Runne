use runne_application::commands::CommandOutcome;
use runne_application::ports::{
    BindPreparedTaskRunProviderRoundEffect, ExecutionNodeId, IdGenerator,
    PreparedTaskRunProviderRequest, TaskRunAssignmentIdentity, TaskRunClaimResult,
    TaskRunProviderBindingError, TaskRunProviderBindingPort,
};
use runne_application::service::ClaimTaskRunInput;

use super::{submit_fence::submit_task_run, support::*};

#[test]
fn d2_budget_is_created_from_real_claim_and_survives_reopen() {
    let database = Database::new("taskrun-tool-budget");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0xa1, "d2-budget-source");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submitted TaskRun expected")
    };
    let (node_id, node_epoch) = {
        let connection = database.connection();
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT authority_id FROM _authority WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let node_id = uuid::Uuid::from_bytes(bytes.try_into().unwrap()).to_string();
        let epoch = runne_store::schema::next_launch_generation(&connection).unwrap();
        runne_store::execution_node::register_local_linux_node(
            &connection,
            *uuid::Uuid::parse_str(&node_id).unwrap().as_bytes(),
            epoch,
            runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
            300,
        )
        .unwrap();
        (node_id, epoch)
    };
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(0xa2, "d2-budget-claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("canonical claim expected")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: claim.fence,
    };
    let version = claim.new_version;
    let first = database
        .store
        .ensure_taskrun_tool_loop_budget(taskrun_id, version, &assignment, 1)
        .unwrap();
    let replay = database
        .store
        .ensure_taskrun_tool_loop_budget(taskrun_id, version, &assignment, 1)
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.taskrun_id, taskrun_id);
    assert_eq!(first.attempt_id, assignment.attempt_id);
    let stale_round = BindPreparedTaskRunProviderRoundEffect {
        identity: assignment.clone(),
        original_claim_version: version,
        current_taskrun_head: version + 1,
        round_index: 0,
        previous_tool_result: None,
        prepared: PreparedTaskRunProviderRequest {
            call_id: runne_provider::ProviderCallId::from_bytes([0xd1; 16]),
            call_digest_version: runne_provider::ProviderCallDigestVersion::V2,
            prepared_digest: [0xd2; 32],
            render_digest: [0xd3; 32],
            profile_digest: [0xd4; 32],
            provider_idempotency_key: "d2-stale-head".into(),
        },
    };
    assert_eq!(
        database
            .store
            .bind_prepared_taskrun_provider_round_effect(stale_round),
        Err(TaskRunProviderBindingError::StaleVersion),
    );
    assert_eq!(first.retry_ordinal, 0);
    assert_eq!(
        first
            .reservation_id
            .to_string()
            .parse::<runne_domain::id::BudgetReservationId>()
            .unwrap(),
        first.reservation_id
    );
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .load_taskrun_tool_loop_budget_ref(taskrun_id)
            .unwrap(),
        Some(first),
    );
}

#[test]
fn store_cycle_ids_are_distinct_canonical_uuid_v7_values() {
    let database = Database::new("taskrun-cycle-id-generator");
    let first = database.store.next_cycle_id().unwrap();
    let second = database.store.next_cycle_id().unwrap();
    assert_ne!(first, second);
    assert_eq!(
        first
            .to_string()
            .parse::<runne_domain::id::CycleId>()
            .unwrap(),
        first
    );
    assert_eq!(
        second
            .to_string()
            .parse::<runne_domain::id::CycleId>()
            .unwrap(),
        second
    );
}
