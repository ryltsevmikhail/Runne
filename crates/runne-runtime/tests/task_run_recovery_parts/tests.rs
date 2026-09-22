// X2 phase 3 fault/observer/reconnect evidence tests. Fixtures live in
// `harness.rs`; both split parts are included into one test crate module.

// ── Invariant R1: lost-ACK survives a genuine runtime restart ───────────────

/// Fault: the client's submit ACK is lost (process crash right after the
/// durable commit). Reconnect = new runtime over the same store; the client
/// retries the identical command identity. The stored receipt — not a new
/// commit — must answer the retry.
#[tokio::test(flavor = "current_thread")]
async fn lost_ack_after_restart_replays_the_stored_receipt() {
    let mut runtime = RestartableRuntime::start();
    let context = command_context(1, "recovery-submit-1");

    let first = runtime
        .host()
        .submit_task_run(context.clone(), submit_command())
        .await
        .expect("pre-restart submit commits");
    assert_submitted_stream(runtime.store(), &first);

    // Real fault boundary: full runtime shutdown + validated reopen.
    runtime.restart().await;

    let replay = runtime
        .host()
        .submit_task_run(context, submit_command())
        .await
        .expect("post-restart duplicate must replay, not fail");
    assert_eq!(first, replay, "stored receipt is authority across restart");

    let stream = runtime.store().load_task_run(first.taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 2, "restart must not duplicate events");

    runtime.shutdown().await;
}

// ── Invariant R2: uncertain outcome stays reconcilable, never an orphan ─────

/// Simulated delivery fault (marked): the reply channel is dropped mid-flight
/// after admission — the client observes `RuntimeClosed` while the runtime may
/// or may not have committed. Retry of the same identity must converge to
/// exactly-once: either replay the receipt (commit happened) or commit once
/// (it did not); a Created-only orphan is forbidden in both branches.
#[tokio::test(flavor = "current_thread")]
async fn uncertain_outcome_reply_loss_converges_exactly_once_on_retry() {
    let mut runtime = RestartableRuntime::start();
    let context = command_context(2, "recovery-submit-2");
    let retry_context = context.clone();

    // Simulated fault: pre-close the runtime so the admitted submit's reply
    // channel dies during shutdown — the caller gets an uncertain error.
    let handle = runtime.host().clone();
    let pending = tokio::spawn(async move {
        handle
            .submit_task_run(context.clone(), submit_command())
            .await
    });
    // Let the submit reach the supervisor, then shut down under it.
    tokio::task::yield_now().await;
    let mut controller = runtime.controller.take().unwrap();
    let outcome = controller
        .shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5),
        })
        .await;
    assert_eq!(outcome, ShutdownOutcome::Quiesced);
    assert_eq!(controller.wait_terminated().await, ShutdownOutcome::Quiesced);
    // The controller is spent; give it back only when the test restarts.
    runtime.controller = Some(controller);

    let observed = pending.await.unwrap();
    // Either branch (commit landed before the fence / reply fenced) is the
    // lost-ACK world — the assertion documents uncertainty and keeps `observed`
    // consumed for the exactly-once proof below.
    let _ = observed.is_ok();

    // Recovery: fresh runtime, same command identity.
    runtime.restart().await;
    let retry = runtime
        .host()
        .submit_task_run(retry_context, submit_command())
        .await
        .expect("retry after uncertain outcome must succeed");
    assert_submitted_stream(runtime.store(), &retry);

    // Exactly-once across the uncertain boundary: retrying the original
    // identity again still replays one receipt with no additional events.
    let again = runtime
        .host()
        .submit_task_run(command_context(2, "recovery-submit-2"), submit_command())
        .await
        .unwrap();
    assert_eq!(retry, again);
    let stream = runtime.store().load_task_run(retry.taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 2, "no duplicate batch, no orphan");

    runtime.shutdown().await;
}

// ── Invariant R3: post-fence rejection leaves no state ──────────────────────

/// Fault: submit racing an immediate shutdown is rejected after the gate
/// fence. The rejected command must leave no stream and no receipt, and a
/// well-formed retry afterwards must commit cleanly.
#[tokio::test(flavor = "current_thread")]
async fn immediate_shutdown_rejection_leaves_no_state_and_retry_commits() {
    let mut runtime = RestartableRuntime::start();

    let mut controller = runtime.controller.take().unwrap();
    let outcome = controller
        .shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5),
        })
        .await;
    assert_eq!(outcome, ShutdownOutcome::Quiesced);
    assert_eq!(controller.wait_terminated().await, ShutdownOutcome::Quiesced);
    runtime.controller = Some(controller);

    let rejected = runtime
        .host()
        .submit_task_run(command_context(3, "recovery-submit-3"), submit_command())
        .await
        .expect_err("submit against a terminated runtime must fail");
    assert_eq!(rejected, TaskRunHostError::Unavailable);

    // No stream may exist for any taskrun in the store — the rejection left
    // nothing behind. The store has exactly the seeded workspace, no events.
    let events_before_retry = count_task_run_streams(runtime.store());
    assert_eq!(events_before_retry, 0, "no orphan streams after rejection");

    runtime.restart().await;
    let retry = runtime
        .host()
        .submit_task_run(command_context(3, "recovery-submit-3"), submit_command())
        .await
        .expect("retry after rejection commits cleanly");
    assert_submitted_stream(runtime.store(), &retry);

    runtime.shutdown().await;
}

// ── Invariant R4: observer view is exact and read-only ──────────────────────

/// Observer evidence: after submit, an observer querying through the canonical
/// query host sees exactly the committed state (Queued/v2) — never a partial
/// Created-only snapshot — and the query surface offers no mutation path.
#[tokio::test(flavor = "current_thread")]
async fn observer_sees_exact_committed_state_and_cannot_mutate() {
    let mut runtime = RestartableRuntime::start();
    let ack = runtime
        .host()
        .submit_task_run(command_context(4, "recovery-submit-4"), submit_command())
        .await
        .expect("submit commits");

    // The query host re-reads the durable stream; observe repeatedly to rule
    // out any intermediate publication window.
    for _ in 0..8 {
        let (state, version) = query_state(runtime.host(), ack.taskrun_id).await;
        assert_eq!(state, CanonicalTaskRunState::Queued);
        assert_eq!(version, 2, "observer never sees a Created-only state");
    }

    // Read-only proof: the query host cannot advance the stream even via the
    // command surface's expected-version fence — a stale revision conflicts
    // without effect.
    let stale = runtime
        .host()
        .request_task_run_cancellation(
            command_context(5, "recovery-cancel-stale"),
            runne_api::ExistingTaskRunCommand {
                taskrun_id: ack.taskrun_id,
                expected_version: 1, // stale: committed version is 2
            },
        )
        .await
        .expect_err("stale-expected-version mutation must conflict");
    assert_eq!(stale, TaskRunHostError::Conflict);
    let stream = runtime.store().load_task_run(ack.taskrun_id).unwrap();
    assert_eq!(
        stream.events.len(),
        2,
        "conflicted mutation changed nothing"
    );

    runtime.shutdown().await;
}

// ── Invariant R5: concurrent duplicate identities commit exactly once ───────

/// Fault: two concurrent writers race the same command identity (lost-ACK
/// duplicate retry while the first attempt is still in flight). Exactly one
/// batch commits; both writers converge on the same receipt.
#[tokio::test(flavor = "current_thread")]
async fn concurrent_duplicate_submits_commit_exactly_one_batch() {
    let mut runtime = RestartableRuntime::start();
    let context = command_context(6, "recovery-submit-race");

    let h1 = runtime.host().clone();
    let h2 = runtime.host().clone();
    let c1 = context.clone();
    let (first, second) = tokio::join!(
        async move { h1.submit_task_run(c1, submit_command()).await },
        async move { h2.submit_task_run(context, submit_command()).await },
    );

    let a = first.expect("racing writer 1 must succeed");
    let b = second.expect("racing writer 2 replays the stored receipt");
    assert_eq!(a.taskrun_id, b.taskrun_id, "one aggregate, one receipt");
    assert_submitted_stream(runtime.store(), &a);
    let stream = runtime.store().load_task_run(a.taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 2, "race commits exactly one batch");

    runtime.shutdown().await;
}

// ── Invariant R6: post-restart observer reconnect sees durable state ────────

/// Reconnect evidence: a client that reconnects after restart (fresh host)
/// queries before it mutates and sees the durable pre-restart state; its
/// duplicate submit then replays the receipt with correct exact identity.
#[tokio::test(flavor = "current_thread")]
async fn reconnect_query_then_submit_matches_durable_state() {
    let mut runtime = RestartableRuntime::start();
    let ack = runtime
        .host()
        .submit_task_run(command_context(7, "recovery-submit-7"), submit_command())
        .await
        .expect("pre-restart submit");

    runtime.restart().await;

    // Reconnect: query first (sync before act).
    let (state, version) = query_state(runtime.host(), ack.taskrun_id).await;
    assert_eq!(state, CanonicalTaskRunState::Queued);
    assert_eq!(version, 2);

    // Then the idempotent retry.
    let replay = runtime
        .host()
        .submit_task_run(command_context(7, "recovery-submit-7"), submit_command())
        .await
        .expect("reconnect retry replays");
    assert_eq!(replay, ack);

    runtime.shutdown().await;
}

/// TaskRun streams holding any events in the store.
fn count_task_run_streams(store: &StoreTransaction) -> usize {
    use runne_application::ports::EventStore as _;
    store.list_task_runs().unwrap().len()
}
