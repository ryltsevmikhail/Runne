#[test]
fn generic_taskrun_commits_refresh_exact_snapshot_without_duplicate_rewrite() {
    let db_path = temp_db_path("snapshot-generic-taskrun");
    cleanup_db(&db_path);
    let (store, service) = open_service(&db_path);
    let context = make_context(91);
    let taskrun_id = match service
        .create_task_run(
            &context,
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap()
    {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {other:?}"),
    };
    let before: (i64, Vec<u8>, Vec<u8>, Vec<u8>) = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row(
            "SELECT aggregate_version, head_event_id, head_integrity_digest, snapshot_integrity_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(before.0, 1);
    assert_eq!(
        service
            .create_task_run(
                &context,
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id()
                }
            )
            .unwrap(),
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version: 1
        }
    );
    let duplicate: (i64, Vec<u8>, Vec<u8>, Vec<u8>) = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row(
            "SELECT aggregate_version, head_event_id, head_integrity_digest, snapshot_integrity_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(duplicate, before);
    service
        .queue_task_run(
            &make_context(92),
            QueueTaskRunInput {
                taskrun_id,
                expected_version: 1,
            },
        )
        .unwrap();
    let after: (i64, Vec<u8>, Vec<u8>, Vec<u8>) = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row(
            "SELECT aggregate_version, head_event_id, head_integrity_digest, snapshot_integrity_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(after.0, 2);
    assert_ne!(after.1, before.1);
    assert_ne!(after.2, before.2);
    assert_ne!(after.3, before.3);
    assert_eq!(store.load_task_run(taskrun_id).unwrap().current_version, 2);
    cleanup_db(&db_path);
}
