//! L2-I: SQLite integration tests for gocode-store.
//!
//! Uses a real temporary SQLite file and `StoreTransaction` for full
//! persistence tests. Tests the complete lifecycle through the service
//! layer, dedup, conflicts, reopen, concurrent writes, clock regression,
//! and fail-closed behavior on schema corruption.

use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::errors::ApplicationError;
use gocode_application::ports::{
    ApplicationCommandContext, EventStore, EventStoreError, LoadedStream, PrincipalId,
    RuntimeAuthorityId, StorageFailureKind,
};
use gocode_application::service::TaskRunService;
use gocode_domain::command::TerminalResult;
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use gocode_domain::task_run::TaskRun;
use gocode_store::store::StoreTransaction;

// ── Helpers ──────────────────────────────────────────────────────────────

fn temp_db_path(name: &str) -> String {
    let mut dir = std::env::temp_dir();
    dir.push(format!("gocode-test-l2i-{}.sqlite", name));
    dir.to_str().unwrap().to_string()
}

fn cleanup_db(db_path: &str) {
    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
}

/// Build a unique `ApplicationCommandContext` per test invocation.
fn make_context(counter: u16) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: CommandId::from_bytes([
            0x01,
            0x8f,
            0x2e,
            0x3a,
            0x70,
            0x00,
            0x70,
            0x00,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            (counter >> 8) as u8,
            counter as u8,
        ]),
        idempotency_key: IdempotencyKey::new(format!("test-key-{}", counter)).unwrap(),
        principal_id: PrincipalId("test-principal".into()),
        actor: Actor::new(format!("test-actor-{}", counter)).unwrap(),
    }
}

const CONV_ID: &str = "018f2e3a-7000-7000-8000-00000000000a";
const WS_ID: &str = "018f2e3a-7000-7000-8000-00000000000b";

fn make_conv_id() -> ConversationId {
    CONV_ID.parse().unwrap()
}

fn make_ws_id() -> WorkspaceId {
    WS_ID.parse().unwrap()
}

fn open_service(
    db_path: &str,
) -> (
    StoreTransaction,
    TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>,
) {
    let store = StoreTransaction::open(db_path, RuntimeAuthorityId("test-host".into())).unwrap();
    let ra_id = store.runtime_authority_id().clone();
    let svc = TaskRunService::new(store.clone(), store.clone(), store.clone(), ra_id);
    (store, svc)
}

// ── Test 1: PRAGMA profile ───────────────────────────────────────────────

#[test]
fn test_pragma_profile() {
    let db_path = temp_db_path("pragma");
    cleanup_db(&db_path);

    let (_store, _svc) = open_service(&db_path);

    // Verify PRAGMAs via direct rusqlite connection
    let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();

    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, "wal", "expected WAL journal mode");

    let synchronous: i32 = conn
        .query_row("PRAGMA synchronous;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(synchronous, 2, "expected FULL synchronous (2)");

    let fk: i32 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(fk, 1, "expected foreign_keys = ON");

    // fullfsync is macOS-only
    #[cfg(target_os = "macos")]
    {
        let fullfsync: i32 = conn
            .query_row("PRAGMA fullfsync;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fullfsync, 1, "expected fullfsync = 1 on macOS");
    }

    cleanup_db(&db_path);
}

// ── Test 2: Full lifecycle ───────────────────────────────────────────────

#[test]
fn test_full_lifecycle() {
    let db_path = temp_db_path("full-lifecycle");
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
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(new_version, 1);
            taskrun_id
        }
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue
    let outcome = svc
        .queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunQueued { new_version: 2, .. }
    ));

    // Admit
    let outcome = svc
        .admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunAdmitted { new_version: 3, .. }
    ));

    // Start attempt
    let outcome = svc
        .start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::AttemptStarted { new_version: 4, .. }
    ));

    // Complete
    let outcome = svc
        .complete_task_run(
            &make_context(5),
            CompleteTaskRunInput {
                taskrun_id: tr_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunCompleted { new_version: 5, .. }
    ));

    cleanup_db(&db_path);
}

// ── Test 3: Replay after reopen ──────────────────────────────────────────

#[test]
fn test_replay_after_reopen() {
    let db_path = temp_db_path("replay-reopen");
    cleanup_db(&db_path);

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
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        };

        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();

        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();

        svc.start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped — connections closed

    // Reopen
    let (store, _svc) = open_service(&db_path);

    // Load stream
    let stream: LoadedStream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 4, "expected 4 events");
    assert_eq!(stream.events.len(), 4);
    assert!(stream.last_event_id.is_some());

    // Verify sequences are consecutive
    for (i, env) in stream.events.iter().enumerate() {
        assert_eq!(
            env.sequence(),
            (i + 1) as u64,
            "sequence mismatch at index {}",
            i
        );
    }

    // Replay aggregate
    let agg = TaskRun::replay(&stream.events).unwrap();
    assert!(
        !agg.state().is_terminal(),
        "aggregate should not be terminal after create+queue+admit+start"
    );

    cleanup_db(&db_path);
}

// ── Test 4: Dedup — repeat command returns original result ────────────────

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

#[test]
fn test_clock_regression() {
    let db_path = temp_db_path("clock-regression");
    cleanup_db(&db_path);

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
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        };

        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped — connections closed, WAL checkpointed

    // Open DB directly and set last_timestamp to a far-future value
    {
        let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute(
            "UPDATE task_run_streams SET last_timestamp = ?1",
            rusqlite::params![i64::MAX],
        )
        .unwrap();
    }

    // Reopen store and try to commit — should detect clock regression.
    // The service maps ClockRegression to StorageFailed(IntegrityViolation).
    let (_store, svc) = open_service(&db_path);

    let err = svc
        .admit_task_run(
            &make_context(5),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap_err();

    assert!(
        matches!(
            err,
            ApplicationError::StorageFailed(StorageFailureKind::IntegrityViolation)
        ),
        "expected StorageFailed(IntegrityViolation) from ClockRegression, got {:?}",
        err,
    );

    cleanup_db(&db_path);
}

// ── Test 8: Two competing writers ────────────────────────────────────────

#[test]
fn test_two_competing_writers() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let db_path = temp_db_path("competing");
    cleanup_db(&db_path);

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
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("{other:?}"),
        };
        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
        tr_id
    };

    let barrier = Arc::new(Barrier::new(2));
    let db = Arc::new(db_path.clone());
    let tr = Arc::new(tr_id);
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = vec![];
    for i in 0..2 {
        let db = Arc::clone(&db);
        let tr = Arc::clone(&tr);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        let ctx = make_context(10 + i);
        handles.push(thread::spawn(move || {
            let store =
                StoreTransaction::open(&db, RuntimeAuthorityId("test-host".into())).unwrap();
            let ra = store.runtime_authority_id().clone();
            let svc = TaskRunService::new(store.clone(), store.clone(), store.clone(), ra);
            barrier.wait();
            let r = svc.admit_task_run(
                &ctx,
                AdmitTaskRunInput {
                    taskrun_id: *tr,
                    expected_version: 2,
                },
            );
            results.lock().unwrap().push(r);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let res = results.lock().unwrap();
    let committed = res.iter().filter(|r| r.is_ok()).count();
    assert_eq!(committed, 1, "exactly one writer must commit, got {res:?}");

    let (_store, _svc) = open_service(&db_path);
    let stream = _store.load_task_run(*tr).unwrap();
    assert_eq!(
        stream.current_version, 3,
        "stream must have exactly 3 events"
    );
    cleanup_db(&db_path);
}

// ── Test 9: WAL reopen — data survives close/reopen ──────────────────────

#[test]
fn test_wal_reopen_data_intact() {
    let db_path = temp_db_path("wal-reopen");
    cleanup_db(&db_path);

    // Phase 1: create + queue + admit
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
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        };

        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();

        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped

    // Phase 2: reopen and verify data intact (WAL mode verified via PRAGMA in Test 1) and continue from version 3
    let (store, svc) = open_service(&db_path);

    // Load stream — should have 3 events
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 3);
    assert_eq!(stream.events.len(), 3);

    // Verify replay works
    let agg = TaskRun::replay(&stream.events).unwrap();
    assert!(!agg.state().is_terminal());

    // Continue: start attempt (version 3 → 4)
    let outcome = svc
        .start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::AttemptStarted { new_version: 4, .. }
    ));

    // Complete (version 4 → 5)
    let outcome = svc
        .complete_task_run(
            &make_context(5),
            CompleteTaskRunInput {
                taskrun_id: tr_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunCompleted { new_version: 5, .. }
    ));

    // Final check via a fresh open: 5 events total
    let (store3, _svc3) = open_service(&db_path);
    let stream = store3.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 5);
    assert_eq!(stream.events.len(), 5);

    cleanup_db(&db_path);
}

// ── Test 10: Schema mismatch — verify fail-closed behavior ────────────────

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
