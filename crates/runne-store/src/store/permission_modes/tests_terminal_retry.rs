//! Supporting lost-result retry with surviving native owner, not daemon restart.
#[path = "tests_admitted_retention/approval.rs"]
mod approval;
#[path = "tests_g2_corrupt_policy/lifecycle.rs"]
mod lifecycle;
#[path = "tests_g2_corrupt_policy/owned.rs"]
mod owned;
#[path = "tests_terminal_retry_support.rs"]
mod support;
#[path = "tests_shell_corpus/terminal.rs"]
mod terminal;

use super::{ceremony, fixture, target};
use runne_application::{
    permission_modes::PermissionMode,
    ports::{CommitError, CommitResult, StorageFailureKind},
};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use std::time::Duration;

#[test]
fn retained_native_child_terminal_retry_preserves_exact_receipt_and_one_effect() {
    // Execute only in a fresh independently reviewed bounded disposable Linux guest.
    let owned_fixture = lifecycle::OwnedFixture::new();
    let f = owned_fixture.get();
    ceremony::commit(f, PermissionMode::RiskBased, 0);
    let shell = std::fs::read("/bin/sh").expect("NOTRUN: installed guest ELF shell");
    assert!(shell.starts_with(b"\x7fELF"));
    let nonce = uuid::Uuid::now_v7().to_string();
    let marker = f.root.path().join("workspace/terminal-retry-marker");
    let effect = format!("{nonce}\n");
    let argv = vec![
        "tool".into(),
        "-c".into(),
        format!("printf '%s\\n' '{nonce}' >> terminal-retry-marker; printf retry-out; printf retry-err >&2"),
    ];
    let (b, prepared) = target::prepare_with_executable(f, argv, &shell);
    let captured = f.store
        .capture_local_command_permission(&b, prepared.observation())
        .unwrap();
    assert_eq!(captured.state, crate::store::LocalCommandAttemptState::ApprovalPending);
    {
        let reader = f.store.inner.reader.lock().unwrap();
        let route: (i64, i64, i64) = reader.query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
            [b.assignment().taskrun_id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(route, (2, 3, 68));
    }
    let approval_id = approval::confirm_native_fixture(f, &b);
    let receipt = f.store.admit_local_command_permission(&b, Some(approval_id)).unwrap();
    let proof = approval::durable(f, &b, approval_id);
    let area = owned::Area::new(&b);
    area.get().prove_empty().unwrap().revalidate().unwrap();
    let mut child = owned::Child::new(
        prepared.bind(b.clone()).unwrap().spawn(area.get(), receipt, &[]).unwrap(),
    );
    assert!(!child.child.was_released());
    assert!(!marker.exists());
    f.store.release_local_command_permission(
        b.assignment(), b.claim_stream_version(), &b, area.get(), &mut child.child,
    ).unwrap();
    assert!(child.child.was_released());
    assert_eq!(child.child.wait_leader(Duration::from_secs(2)).unwrap(),
        LinuxLeaderExitKindV1::Exited { code: 0 });
    let output = support::Output::drain(&mut child.child);
    child.evidence(area.get());
    assert_eq!(std::fs::read(&marker).unwrap(), effect.as_bytes());
    let payload = terminal::success(f, b.assignment().taskrun_id);
    let expected = payload.command_result.clone();
    let original = payload.clone();
    let version = payload.expected_version + 1;
    // Oracle observes commit; simulated caller retries without rebuilding terminal intent.
    assert_eq!(f.store.commit_local_command_permission_terminal(
        payload, b.assignment(), &b, &child.child, output.exact(),
    ).unwrap(), CommitResult::Committed { new_version: version });
    terminal::assert_success(f, b.assignment().taskrun_id, version);
    support::assert_single_terminal(f, b.assignment().taskrun_id, &original);
    let before = support::snapshot(f);
    let retry = |payload, output| f.store.commit_local_command_permission_terminal(
        payload, b.assignment(), &b, &child.child, output,
    );
    assert_eq!(retry(original.clone(), output.exact()).unwrap(),
        CommitResult::Duplicate { stored_result: expected.clone() });
    assert_eq!(support::snapshot(f), before);
    assert_eq!(retry(original.clone(), output.altered()),
        Err(CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)));
    assert_eq!(support::snapshot(f), before);
    assert_eq!(retry(original.clone(), output.exact()).unwrap(),
        CommitResult::Duplicate { stored_result: expected.clone() });
    let mut changed_key = original.clone();
    changed_key.idempotency_key = fixture::key("terminal-retry-changed-key");
    assert!(matches!(retry(changed_key, output.exact()),
        Err(CommitError::IdempotencyConflict { .. })));
    assert_eq!(support::snapshot(f), before);
    assert_eq!(retry(original.clone(), output.exact()).unwrap(),
        CommitResult::Duplicate { stored_result: expected });
    assert_eq!(support::snapshot(f), before);
    assert_eq!(std::fs::read(&marker).unwrap(), effect.as_bytes());
    assert_eq!(approval::durable(f, &b, approval_id), proof);
    terminal::assert_success(f, b.assignment().taskrun_id, version);
    support::assert_single_terminal(f, b.assignment().taskrun_id, &original);
    child.evidence(area.get());
    child.disarm();
    drop(child);
    area.finish();
}
