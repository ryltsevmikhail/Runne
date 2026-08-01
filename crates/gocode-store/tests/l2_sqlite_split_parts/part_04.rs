#[test]
fn test_dedup_repeat_command() {
    let db_path = temp_db_path("dedup");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);

    let ctx = make_context(1);
    let input = CreateTaskRunInput {
        conversation_id: make_conv_id(),
        workspace_id: make_ws_id(),
    };

    // First call
    let first = svc.create_task_run(&ctx, input.clone()).unwrap();
    let tr_id = match first {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(new_version, 1);
            taskrun_id
        }
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Repeat with same context → dedup, same result
    let second = svc.create_task_run(&ctx, input).unwrap();
    match second {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(taskrun_id, tr_id, "dedup should return same taskrun_id");
            assert_eq!(new_version, 1, "dedup should return same version");
        }
        other => panic!("expected TaskRunCreated (dedup), got {:?}", other),
    }

    // Verify events NOT duplicated: version should still be 1
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 1, "events should not be duplicated");
    assert_eq!(stream.events.len(), 1);

    // Queue dedup
    let ctx_q = make_context(2);
    svc.queue_task_run(
        &ctx_q,
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap(); // version now 2

    // Repeat queue with same context → dedup
    let retry = svc
        .queue_task_run(
            &ctx_q,
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        retry,
        CommandOutcome::TaskRunQueued { new_version: 2, .. }
    ));

    // Check stream: should still have 2 events, not 3
    let stream2 = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream2.current_version, 2);
    assert_eq!(stream2.events.len(), 2);

    cleanup_db(&db_path);
}

// ── Test 5: VersionConflict — stale expected_version ─────────────────────

#[test]
fn test_version_conflict() {
    let db_path = temp_db_path("version-conflict");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);

    // Create (version 1)
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let tr_id = match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue at version 1 → success (version becomes 2)
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap();

    // Queue again at version 1 (stale) → VersionConflict
    let err = svc
        .queue_task_run(
            &make_context(3),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap_err();

    assert!(
        matches!(
            err,
            ApplicationError::VersionConflict {
                expected: 1,
                actual: 2
            }
        ),
        "expected VersionConflict, got {:?}",
        err,
    );

    // Verify stream was NOT modified (still version 2)
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(
        stream.current_version, 2,
        "stream should be unchanged after conflict"
    );
    assert_eq!(stream.events.len(), 2);

    cleanup_db(&db_path);
}

// ── Test 6: IdempotencyConflict — same scope+key, different fingerprint ──

#[test]
fn test_idempotency_conflict_different_fingerprint() {
    let db_path = temp_db_path("idem-conflict");
    cleanup_db(&db_path);

    let (_store, svc) = open_service(&db_path);

    // Create
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let tr_id = match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue at version 1 with idempotency key from context(2)
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap();

    // Same idempotency_key ("test-key-2"), different CommandId and expected_version
    // → different fingerprint. Scope+key matches → IdempotencyConflict.
    let conflict_ctx = ApplicationCommandContext {
        command_id: CommandId::from_bytes([
            0x02, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x99,
        ]),
        idempotency_key: IdempotencyKey::new("test-key-2").unwrap(),
        principal_id: PrincipalId("test-principal".into()),
        actor: Actor::new("test-actor-99").unwrap(),
    };
    let err = svc
        .queue_task_run(
            &conflict_ctx,
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap_err();

    assert!(
        matches!(err, ApplicationError::IdempotencyConflict { .. }),
        "expected IdempotencyConflict, got {:?}",
        err,
    );

    cleanup_db(&db_path);
}

// ── Test 7: ClockRegression — reject timestamps going backwards ──────────
