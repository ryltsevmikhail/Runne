#[test]
fn test_schema_mismatch_fail_closed() {
    let db_path = temp_db_path("schema-mismatch");
    cleanup_db(&db_path);

    // Phase 1: create a valid store with data
    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);

        let outcome = svc
            .create_task_run(
                &make_context(1),
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id(),
                },
            )
            .unwrap();
        match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        }
    }; // store dropped

    // Phase 2: corrupt the DB by dropping the events table
    {
        let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        // Drop the events table — integrity_check checks internal b-tree
        // integrity, not application table presence, so reopen won't fail.
        conn.execute_batch("DROP TABLE events;").unwrap();
    }

    // Phase 3: reopen — should succeed (PRAGMA integrity_check passes)
    let (store, _svc) = open_service(&db_path);

    // Phase 4: try to load the stream — should fail because events table is missing
    let result = store.load_task_run(tr_id);
    assert!(
        result.is_err(),
        "loading with missing tables should fail — fail-closed"
    );
    match result {
        Err(EventStoreError::CorruptData) => {
            // Expected: fail-closed on corrupted schema
        }
        other => panic!("expected CorruptData, got {:?}", other),
    }

    cleanup_db(&db_path);
}
