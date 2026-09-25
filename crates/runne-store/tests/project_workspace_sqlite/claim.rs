use runne_application::commands::CommandOutcome;
use runne_application::ports::{
    EventStore, ExecutionNodeId, TaskRunClaimError, TaskRunClaimLookup, TaskRunClaimLookupResult,
    TaskRunClaimPort, TaskRunClaimRequest, TaskRunClaimResult,
};
use runne_application::service::ClaimTaskRunInput;

use super::submit_fence::submit_task_run;
use super::support::*;
use std::sync::{Arc, Barrier};

pub(super) fn node_registration(database: &Database) -> (String, u64) {
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
        30,
    )
    .unwrap();
    (node_id, epoch)
}

#[test]
fn taskrun_claim_replays_the_exact_receipt_after_restart() {
    let database = Database::new("taskrun-claim-restart");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x91, "claim-source");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    let (node_id, node_epoch) = node_registration(&database);
    let context = task_context(0x92, "claim-command");
    let input = ClaimTaskRunInput {
        taskrun_id,
        expected_version: 2,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        capability_descriptor: "linux-executor-v1".into(),
        lease_duration_ms: 30_000,
    };

    let first = database
        .task_runs()
        .claim_task_run(&context, input.clone(), &database.store)
        .unwrap();
    let receipt = match &first {
        runne_application::ports::TaskRunClaimResult::Committed(receipt) => receipt.clone(),
        _ => panic!("first call must commit"),
    };
    let same_process = database
        .task_runs()
        .claim_task_run(&context, input.clone(), &database.store)
        .unwrap();
    assert_eq!(
        same_process,
        runne_application::ports::TaskRunClaimResult::Duplicate(receipt.clone())
    );

    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let reopened_service = runne_application::service::TaskRunService::new(
        reopened.clone(),
        reopened.clone(),
        reopened.clone(),
        authority(),
    );
    let after_restart = reopened_service
        .claim_task_run(&context, input, &reopened)
        .unwrap();
    assert_eq!(
        after_restart,
        runne_application::ports::TaskRunClaimResult::Duplicate(receipt)
    );
    assert_eq!(
        reopened.load_task_run(taskrun_id).unwrap().current_version,
        4
    );
    let connection = database.connection();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM taskrun_assignments", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        4
    );
}

#[derive(Clone)]
struct BarrierPort {
    store: runne_store::store::StoreTransaction,
    lookups: Arc<Barrier>,
}

impl TaskRunClaimPort for BarrierPort {
    fn lookup_task_run_claim(
        &self,
        lookup: TaskRunClaimLookup,
    ) -> Result<TaskRunClaimLookupResult, TaskRunClaimError> {
        let result = self.store.lookup_task_run_claim(lookup)?;
        self.lookups.wait();
        Ok(result)
    }

    fn claim_task_run(
        &self,
        request: TaskRunClaimRequest,
    ) -> Result<TaskRunClaimResult, TaskRunClaimError> {
        self.store.claim_task_run(request)
    }
}

#[test]
fn concurrent_exact_claims_commit_one_assignment_and_replay_one_receipt() {
    let database = Database::new("taskrun-claim-race");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x95, "claim-race-source");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    let (node, epoch) = node_registration(&database);
    let context = task_context(0x96, "claim-race");
    let input = ClaimTaskRunInput {
        taskrun_id,
        expected_version: 2,
        node_id: ExecutionNodeId(node),
        node_epoch: epoch,
        capability_descriptor: "linux-executor-v1".into(),
        lease_duration_ms: 25_000,
    };
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = database.store.clone();
        let context = context.clone();
        let input = input.clone();
        let port = BarrierPort {
            store: store.clone(),
            lookups: barrier.clone(),
        };
        handles.push(std::thread::spawn(move || {
            let service = runne_application::service::TaskRunService::new(
                store.clone(),
                store.clone(),
                store,
                authority(),
            );
            service.claim_task_run(&context, input, &port).unwrap()
        }));
    }
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, TaskRunClaimResult::Committed(_)))
            .count(),
        1,
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, TaskRunClaimResult::Duplicate(_)))
            .count(),
        1,
    );
    let receipt_a = match &results[0] {
        TaskRunClaimResult::Committed(receipt) | TaskRunClaimResult::Duplicate(receipt) => receipt,
    };
    let receipt_b = match &results[1] {
        TaskRunClaimResult::Committed(receipt) | TaskRunClaimResult::Duplicate(receipt) => receipt,
    };
    assert_eq!(receipt_a, receipt_b);
    assert_eq!(receipt_a.taskrun_id, taskrun_id);
    let connection = database.connection();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM taskrun_assignments", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        4
    );
}
