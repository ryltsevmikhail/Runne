//! Guest-only physical ordered API histories; not overlap/crash/Human qualification.
#[path = "tests_native_ordered/concurrent_fence.rs"]
mod concurrent_fence;
#[path = "tests_native_ordered/concurrent_race.rs"]
mod concurrent_race;
#[path = "tests_native_ordered/concurrent_workers.rs"]
mod concurrent_workers;
#[path = "tests_native_ordered/concurrent_revoke.rs"]
mod concurrent_revoke;
#[path = "tests_native_ordered/receipts.rs"]
mod receipts;
#[path = "tests_native_ordered/support.rs"]
mod support;
#[path = "tests_native_ordered/terminal.rs"]
mod terminal;

use super::fixture::{command_id, key};
use runne_application::{
    commands::{CancelTaskRunInput, CommandOutcome},
    ports::{ApplicationCommandContext, CommitResult, EventStore, EventStoreError, PrincipalId},
    service::TaskRunService,
};
use runne_domain::{event::Actor, task_run::TaskRunEvent};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use std::time::{Duration, Instant};
use support::{Area, Child};

#[test]
fn durable_revoke_before_go_prevents_effect_and_settles_public_cancellation() {
    let (f, b, prepared, receipt, original_approval) = support::admitted();
    let original = f
        .store
        .load_local_command_permission_capture(b.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    let area = Area::new(&b);
    let mut child = Child::new(
        prepared
            .bind(b.clone())
            .unwrap()
            .spawn(area.get(), receipt, &[])
            .unwrap(),
    );
    assert!(area.get().is_populated().unwrap());
    assert!(!child.child.was_released());
    support::revoke(&f);
    assert_eq!(
        f.store.observe_local_command_permission_policy(&b),
        Ok(Some(3))
    );
    assert_eq!(
        f.store.release_local_command_permission(
            b.assignment(),
            b.claim_stream_version(),
            &b,
            area.get(),
            &mut child.child
        ),
        Err(EventStoreError::CorruptData)
    );
    assert!(!child.child.was_released());
    assert_eq!(receipts::spent(&f, &b), 0);
    assert!(!support::marker(&f).exists());
    let unchanged = f
        .store
        .load_local_command_permission_capture(b.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged, original);
    assert_eq!(
        super::approval::durable(&f, &b, original_approval.0),
        original_approval.1,
        "refused release preserves exact original admission and human proof linkage"
    );
    let taskrun_id = b.assignment().taskrun_id;
    let stream = f.store.load_task_run(taskrun_id).unwrap();
    let outcome = TaskRunService::new(
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
        f.scope.runtime_authority_id.clone(),
    )
    .cancel_task_run(
        &ApplicationCommandContext {
            command_id: command_id(),
            idempotency_key: key("r05-cancel"),
            principal_id: PrincipalId(f.principal.as_str().into()),
            actor: Actor::new("test:r05-fixture").unwrap(),
        },
        CancelTaskRunInput {
            taskrun_id,
            expected_version: stream.current_version,
        },
    )
    .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunCancellationRequested { .. }
    ));
    assert!(matches!(
        f.store
            .load_task_run(taskrun_id)
            .unwrap()
            .events
            .last()
            .unwrap()
            .payload(),
        TaskRunEvent::CancellationRequested
    ));
    assert_eq!(
        f.store
            .local_command_permission_stop_reason(b.assignment(), &b)
            .unwrap(),
        Some(1)
    );
    receipts::stop_anchor(&f, &b, 1);
    child.stopped();
    let empty = area.get().prove_empty().unwrap();
    f.store
        .complete_local_command_permission_cancelled_before_release(b.assignment(), &b, empty)
        .unwrap();
    receipts::settled(&f, &b, &area.get().identity().to_bytes(), false);
    assert!(!support::marker(&f).exists());
    drop(child);
    area.finish();
}

#[test]
fn go_and_natural_exit_before_revoke_settle_factual_effect_as_policy_stopped() {
    let (f, b, prepared, receipt, _original_approval) = support::admitted();
    let area = Area::new(&b);
    let mut child = Child::new(
        prepared
            .bind(b.clone())
            .unwrap()
            .spawn(area.get(), receipt, &[])
            .unwrap(),
    );
    assert!(area.get().is_populated().unwrap());
    assert!(!support::marker(&f).exists());
    f.store
        .release_local_command_permission(
            b.assignment(),
            b.claim_stream_version(),
            &b,
            area.get(),
            &mut child.child,
        )
        .unwrap();
    assert!(child.child.was_released());
    assert_eq!(receipts::spent(&f, &b), 1);
    assert_eq!(
        child.child.wait_leader(Duration::from_secs(2)).unwrap(),
        LinuxLeaderExitKindV1::Exited { code: 0 }
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let chunk = loop {
        child.child.poll_output().unwrap();
        let chunk = child.child.take_output();
        assert!(chunk.stdout.is_empty() && chunk.stderr.is_empty());
        assert_eq!(
            (chunk.stdout_observed_bytes, chunk.stderr_observed_bytes),
            (0, 0)
        );
        assert!(
            !chunk.stdout_truncated && !chunk.stderr_truncated && !chunk.observed_bytes_overflowed
        );
        if chunk.stdout_eof && chunk.stderr_eof {
            break chunk;
        }
        assert!(Instant::now() < deadline, "bounded EOF wait");
        std::thread::sleep(Duration::from_millis(5));
    };
    child
        .child
        .terminal_evidence()
        .unwrap()
        .revalidate_empty_area()
        .unwrap();
    child.exited();
    assert_eq!(std::fs::read(support::marker(&f)).unwrap(), b"once");
    support::revoke(&f);
    assert_eq!(
        f.store.observe_local_command_permission_policy(&b),
        Ok(Some(3))
    );
    let reason = f
        .store
        .observe_local_command_permission_policy(&b)
        .unwrap()
        .unwrap();
    assert_eq!(
        f.store
            .record_local_command_permission_stop(b.assignment(), &b, reason)
            .unwrap(),
        3
    );
    receipts::stop_anchor(&f, &b, 3);
    let output = crate::store::LocalCommandPermissionTerminalOutputV1::new(
        chunk.stdout,
        chunk.stderr,
        chunk.stdout_observed_bytes,
        chunk.stderr_observed_bytes,
        chunk.stdout_truncated,
        chunk.stderr_truncated,
        chunk.stdout_eof,
        chunk.stderr_eof,
        chunk.observed_bytes_overflowed,
    )
    .unwrap();
    let payload = terminal::policy_stopped(&f, b.assignment().taskrun_id);
    assert!(matches!(
        f.store
            .commit_local_command_permission_terminal(
                payload,
                b.assignment(),
                &b,
                &child.child,
                output
            )
            .unwrap(),
        CommitResult::Committed { .. }
    ));
    receipts::settled(&f, &b, &area.get().identity().to_bytes(), true);
    // Same-handle early guard only: this is not new-ID or restart dedup evidence.
    assert_eq!(
        f.store.release_local_command_permission(
            b.assignment(),
            b.claim_stream_version(),
            &b,
            area.get(),
            &mut child.child
        ),
        Err(EventStoreError::CorruptData)
    );
    assert_eq!(receipts::spent(&f, &b), 1);
    assert_eq!(std::fs::read(support::marker(&f)).unwrap(), b"once");
    drop(child);
    area.finish();
}

#[path = "tests_native_ordered/live_revoke.rs"]
mod live_revoke;
