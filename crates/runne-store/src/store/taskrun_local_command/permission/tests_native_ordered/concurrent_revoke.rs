//! One concurrent effect-wins history; no reverse-order/full R05/Human claim.
#[path = "../../../permission_modes/tests_g2_corrupt_policy/lifecycle.rs"]
mod lifecycle;
#[path = "../../../permission_modes/tests_g2_corrupt_policy/owned.rs"]
mod owned;
#[path = "live_revoke_output.rs"]
mod output;
#[path = "../../../permission_modes/tests_terminal_retry_support.rs"]
mod rows;

// Every path-reused helper resolves this same Fixture type instance.
use super::super::{approval, ceremony, fixture, target};
use super::{concurrent_race::Race, terminal};
use runne_application::{
    permission_modes::PermissionMode,
    ports::{CommitError, CommitResult, EventStoreError, StorageFailureKind},
};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;

#[test]
fn effect_before_concurrent_durable_revoke_preserves_terminal_barrier() {
    // Never execute on host; requires separately reviewed bounded disposable guest.
    let race = Race::new();
    let control = race.control.clone();
    let owned_fixture = lifecycle::OwnedFixture::with_fence(move |owner| control.decorate(owner));
    let f = owned_fixture.get();
    ceremony::commit(f, PermissionMode::RiskBased, 0);
    let shell = std::fs::read("/bin/sh").expect("NOTRUN: installed guest shell");
    assert!(shell.starts_with(b"\x7fELF"));
    let nonce = uuid::Uuid::now_v7().to_string();
    let workspace = f.root.path().join("workspace");
    let marker = workspace.join("live-revoke-marker");
    let release = workspace.join("live-revoke-release");
    let late = workspace.join("live-revoke-late");
    assert!(!marker.exists() && !release.exists() && !late.exists());
    // Finite builtins-only loop; exhaustion exits 93 and fails live assertions.
    // Guest CPU15/wall60 additionally bound it; no sleep process or live network.
    let script = format!(
        "printf '%s\\n' '{nonce}' >> live-revoke-marker; printf ready; \
         n=0; while [ ! -f live-revoke-release ]; do \
         n=$((n+1)); if [ \"$n\" -ge 10000000 ]; then exit 93; fi; done; \
         printf late >> live-revoke-late"
    );
    let (b, prepared) = target::prepare_with_executable(
        f, vec!["tool".into(), "-c".into(), script], &shell,
    );
    f.store.capture_local_command_permission(&b, prepared.observation()).unwrap();
    let approval_id = approval::confirm_native_fixture(f, &b);
    let receipt = f.store.admit_local_command_permission(&b, Some(approval_id)).unwrap();
    let proof = approval::durable(f, &b, approval_id);
    let area = owned::Area::new(&b);
    let mut child = owned::Child::new(
        prepared.bind(b.clone()).unwrap().spawn(area.get(), receipt, &[]).unwrap(),
    );
    assert!(!child.child.was_released());
    let mut immutable_before = f.store.load_local_command_permission_capture(
        b.assignment().taskrun_id,
    ).unwrap().unwrap();
    // Race8s includes worker setup. Ready/drain/stop have separate bounded cleanup budgets.
    race.run(f, &marker, format!("{nonce}\n").as_bytes(), || {
        f.store.release_local_command_permission(
            b.assignment(), b.claim_stream_version(), &b, area.get(), &mut child.child,
        )
    }).expect("actual pending revoke contention and nonce under retained lease");
    assert!(child.child.was_released());
    let mut output = output::Output::ready(&mut child.child);
    output.assert_live(&mut child.child, area.get());
    assert_eq!(std::fs::read(&marker).unwrap(), format!("{nonce}\n").as_bytes());
    let original = f.store.load_local_command_permission_capture(
        b.assignment().taskrun_id,
    ).unwrap().unwrap();
    // GO changes only capture's mutable attempt state; compare every immutable field.
    immutable_before.state = original.state;
    assert_eq!(immutable_before, original);
    assert_eq!(approval::durable(f, &b, approval_id), proof);
    assert_eq!(f.store.observe_local_command_permission_policy(&b), Ok(Some(3)));
    output.assert_live(&mut child.child, area.get());
    assert_eq!(f.store.record_local_command_permission_stop(
        b.assignment(), &b, 3,
    ).unwrap(), 3);
    assert_eq!(f.store.local_command_permission_stop_reason(
        b.assignment(), &b,
    ).unwrap(), Some(3));
    assert_eq!(approval::durable(f, &b, approval_id), proof);
    assert_eq!(f.store.load_local_command_permission_capture(
        b.assignment().taskrun_id,
    ).unwrap().unwrap(), original);
    output::assert_running(f, &b);
    // Allocate intent/event IDs before the no-change snapshot; clone exactly once.
    let payload = terminal::policy_stopped(f, b.assignment().taskrun_id);
    let expected = payload.command_result.clone();
    let before = rows::snapshot(f);
    // Deliberately false EOF flags: adversarial input, never readiness evidence.
    assert_eq!(f.store.commit_local_command_permission_terminal(
        payload.clone(), b.assignment(), &b, &child.child, output.forged_eof(),
    ), Err(CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)));
    assert_eq!(rows::snapshot(f), before);
    output.assert_live(&mut child.child, area.get());
    output::assert_running(f, &b);
    assert!(!release.exists() && !late.exists());
    child.stop_reap();
    output.drain(&mut child.child);
    child.evidence(area.get());
    assert!(matches!(child.child.terminal_evidence().unwrap().leader_exit_kind(),
        LinuxLeaderExitKindV1::Signaled { .. }));
    assert_eq!(f.store.commit_local_command_permission_terminal(
        payload.clone(), b.assignment(), &b, &child.child, output.real_eof(),
    ).unwrap(), CommitResult::Committed { new_version: payload.expected_version + 1 });
    rows::assert_single_terminal(f, b.assignment().taskrun_id, &payload);
    let settled = rows::snapshot(f);
    assert_eq!(f.store.commit_local_command_permission_terminal(
        payload.clone(), b.assignment(), &b, &child.child, output.real_eof(),
    ).unwrap(), CommitResult::Duplicate { stored_result: expected });
    assert_eq!(rows::snapshot(f), settled);
    assert_eq!(f.store.release_local_command_permission(
        b.assignment(), b.claim_stream_version(), &b, area.get(), &mut child.child,
    ), Err(EventStoreError::CorruptData));
    assert_eq!(rows::snapshot(f), settled);
    std::fs::write(&release, b"release only after verified stop").unwrap();
    assert_eq!(std::fs::read(&marker).unwrap(), format!("{nonce}\n").as_bytes());
    assert!(!late.exists());
    assert_eq!(approval::durable(f, &b, approval_id), proof);
    child.evidence(area.get());
    child.disarm();
    drop(child);
    area.finish();
    // owned_fixture closes Store/trust/native handles before fallible RAM removal.
}
