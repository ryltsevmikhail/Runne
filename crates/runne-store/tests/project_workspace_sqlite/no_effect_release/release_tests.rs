use super::*;

#[test]
fn release_replays_and_frees_node_capacity() {
    let database = Database::new("taskrun-no-effect-release");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let first = submit_task_run(&database, 0xc1, "release-first");
    let second = submit_task_run(&database, 0xc2, "release-second");
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: first, ..
    } = first
    else {
        panic!()
    };
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: second, ..
    } = second
    else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, first, 0xc3, &node, epoch);
    let request = release_request(&database, identity.clone(), version, 0xc4);
    let released = database
        .store
        .release_taskrun_no_effect(request.clone())
        .unwrap();
    let TaskRunNoEffectReleaseResult::Released(receipt) = released else {
        panic!("release")
    };
    assert_eq!(
        database.store.release_taskrun_no_effect(request).unwrap(),
        TaskRunNoEffectReleaseResult::Duplicate(receipt)
    );
    let second_claim = database
        .task_runs()
        .claim_task_run(
            &task_context(0xc5, "second-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id: second,
                expected_version: 2,
                node_id: ExecutionNodeId(node),
                node_epoch: epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    assert!(matches!(second_claim, TaskRunClaimResult::Committed(_)));
}

#[test]
fn release_rejects_stale_expected_version_without_mutation() {
    let database = Database::new("taskrun-release-stale-version");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(&database, 0x31, "release-stale-version");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, taskrun_id, 0x32, &node, epoch);
    let mut request = release_request(&database, identity.clone(), version, 0x33);
    request.expected_version -= 1;

    assert_eq!(
        database.store.release_taskrun_no_effect(request),
        Err(TaskRunNoEffectReleaseError::StaleVersion {
            expected: version - 1,
            actual: version,
        })
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        version
    );
    let state: String = database
        .connection()
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "active");
}

#[test]
fn current_route_without_capture_cannot_release() {
    let database = Database::new("taskrun-release-current-no-capture");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(&database, 0x35, "release-current-no-capture");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, taskrun_id, 0x36, &node, epoch);
    {
        let connection = database.connection();
        connection
            .execute(
                "INSERT INTO taskrun_local_command_attempts
             (taskrun_id,conversation_id,workspace_id,command_digest,state,updated_at)
             VALUES (?1,?2,?3,?4,'preflight',1)",
                rusqlite::params![
                    taskrun_id.as_bytes(),
                    [0x41_u8; 16].as_slice(),
                    [0x42_u8; 16].as_slice(),
                    [0x43_u8; 32].as_slice()
                ],
            )
            .unwrap();
        connection.execute(
            "INSERT INTO taskrun_local_permission_routes(taskrun_id,route,provenance,cutover_version)
             VALUES (?1,2,3,68)",
            [taskrun_id.as_bytes()],
        ).unwrap();
    }
    assert_eq!(
        database
            .store
            .release_taskrun_no_effect(release_request(&database, identity, version, 0x37)),
        Err(TaskRunNoEffectReleaseError::DispatchMayHaveStarted)
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        version
    );
}
