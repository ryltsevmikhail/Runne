// Shared fixtures. Imports and constants live in `store.rs`; both files are
// included into one test crate module.

fn conversation_id() -> ConversationId {
    CONVERSATION_ID.parse().unwrap()
}

fn workspace_id() -> WorkspaceId {
    OTHER_WORKSPACE_ID.parse().unwrap()
}

fn context(sequence: u8, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000001{:02x}", sequence)
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("runne-test").unwrap(),
    }
}

fn make_service() -> (TaskRunService<StrictMemStore, StrictMemStore, StrictMemStore>, StrictMemStore)
{
    let store = StrictMemStore::new();
    let service = TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        RuntimeAuthorityId("test-authority".into()),
    );
    (service, store)
}

fn submit_input() -> SubmitTaskRunInput {
    SubmitTaskRunInput {
        conversation_id: conversation_id(),
        workspace_id: workspace_id(),
    }
}

// ── Atomic submit ──────────────────────────────────────────────────────────

#[test]
fn submit_commits_created_then_queued_as_one_atomic_unit_of_work() {
    let (service, store) = make_service();
    let outcome = service
        .submit_task_run(&context(1, "submit-1"), submit_input())
        .expect("submit must commit");
    assert_eq!(
        outcome,
        CommandOutcome::TaskRunSubmitted {
            taskrun_id: TASKRUN_ID.parse().unwrap(),
            new_version: 2,
        }
    );

    let taskrun_id = TASKRUN_ID.parse().unwrap();
    let stream = store.stream(taskrun_id);
    assert_eq!(stream.len(), 2, "submit appends exactly two events");
    assert_eq!(stream[0].sequence(), 1);
    assert_eq!(stream[0].payload(), &TaskRunEvent::TaskRunCreated);
    assert_eq!(stream[1].sequence(), 2);
    assert_eq!(stream[1].payload(), &TaskRunEvent::TaskRunQueued);
    assert_eq!(
        stream[1].causation_id(),
        Some(stream[0].event_id()),
        "queued event causally chains to the created event"
    );
    assert_eq!(store.commits(), 1, "submit performs exactly one commit");

    let replayed = TaskRun::replay(&stream).expect("committed batch must replay");
    assert_eq!(replayed.state(), TaskRunState::Queued);
}

// ── Lost-ack reconciliation ────────────────────────────────────────────────

#[test]
fn duplicate_submit_same_identity_and_payload_returns_the_stored_ack() {
    let (service, store) = make_service();
    let first = service
        .submit_task_run(&context(1, "submit-1"), submit_input())
        .expect("first submit");
    let duplicate = service
        .submit_task_run(&context(1, "submit-1"), submit_input())
        .expect("duplicate identity replays the stored ack");
    assert_eq!(first, duplicate);
    assert_eq!(store.commits(), 1, "duplicate must not commit again");
    assert_eq!(store.stream(TASKRUN_ID.parse().unwrap()).len(), 2);
}

#[test]
fn regenerated_command_id_under_the_same_idempotency_key_conflicts() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-1"), submit_input())
        .expect("first submit");
    let error = service
        .submit_task_run(&context(2, "submit-1"), submit_input())
        .expect_err("same scope and key with a regenerated command ID must conflict");
    assert!(matches!(
        error,
        ApplicationError::IdempotencyConflict { .. }
    ));
    assert_eq!(store.commits(), 1);
    assert_eq!(
        store.stream(TASKRUN_ID.parse().unwrap()).len(),
        2,
        "conflict must not append a second stream"
    );
}

#[test]
fn duplicate_submit_with_a_different_payload_conflicts() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-1"), submit_input())
        .expect("first submit");
    let conflicting = SubmitTaskRunInput {
        conversation_id: conversation_id(),
        workspace_id: "018f2e3a-7000-7000-8000-0000000000bb".parse().unwrap(),
    };
    let error = service
        .submit_task_run(&context(1, "submit-1"), conflicting)
        .expect_err("changed payload under the same identity must conflict");
    assert!(matches!(
        error,
        ApplicationError::IdempotencyConflict { .. }
    ));
    assert_eq!(store.commits(), 1);
    let stream = store.stream(TASKRUN_ID.parse().unwrap());
    assert_eq!(stream.len(), 2, "conflict must not mutate the stream");
    assert_eq!(stream[1].payload(), &TaskRunEvent::TaskRunQueued);
}

// ── Failure boundaries ─────────────────────────────────────────────────────

#[test]
fn failure_before_commit_leaves_no_created_only_orphan() {
    let (service, store) = make_service();
    store.fail_next_commit();
    let error = service
        .submit_task_run(&context(1, "submit-1"), submit_input())
        .expect_err("injected storage failure must surface");
    assert!(matches!(
        error,
        ApplicationError::StorageFailed(StorageFailureKind::Unavailable)
    ));
    assert!(
        store.stream(TASKRUN_ID.parse().unwrap()).is_empty(),
        "a failed submit must not leave a Created-only partial stream"
    );
    assert_eq!(store.commits(), 1, "the failed attempt counted one commit");

    // A fresh identity is a brand-new command: the pipeline draws the next
    // generator id, so the retry owns a different taskrun aggregate.
    let recovered = service
        .submit_task_run(&context(2, "submit-2"), submit_input())
        .expect("a fresh identity submits after the failure");
    assert_eq!(
        recovered,
        CommandOutcome::TaskRunSubmitted {
            taskrun_id: RETRY_TASKRUN_ID.parse().unwrap(),
            new_version: 2,
        }
    );
    assert_eq!(
        store.stream(RETRY_TASKRUN_ID.parse().unwrap()).len(),
        2,
        "the retry commits its own Created + Queued batch"
    );
    assert!(
        store.stream(TASKRUN_ID.parse().unwrap()).is_empty(),
        "the failed attempt still leaves no Created-only orphan"
    );
}
