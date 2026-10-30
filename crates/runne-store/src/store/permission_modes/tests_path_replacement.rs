//! One ordered owned-path replacement; guest-only logical fixture authority.
#[path = "tests_admitted_retention/approval.rs"]
mod approval;
#[path = "tests_g2_corrupt_policy/lifecycle.rs"]
mod lifecycle;
#[path = "tests_g2_corrupt_policy/owned.rs"]
mod owned;
#[path = "tests_path_replacement/paths.rs"]
mod paths;
#[path = "tests_shell_corpus/terminal.rs"]
mod terminal;

use super::{ceremony, fixture, target};
use crate::store::LocalCommandAttemptState;
use lifecycle::OwnedFixture;
use owned::{Area, Child};
use paths::Paths;
use runne_application::{permission_modes::PermissionMode, ports::CommitResult};
use runne_platform::local_command_linux::{
    LinuxCommandError, LinuxLeaderExitKindV1, SealedExecutableSnapshot,
};
use std::{fs::File, time::Duration};

#[test]
fn owned_executable_symlink_replacement_refuses_rebind_preserves_original_go() {
    // Only a fresh separately reviewed disposable guest may execute this test.
    let fixture = OwnedFixture::new();
    let f = fixture.get();
    let shell = std::fs::read("/bin/sh").expect("NOTRUN: installed ELF shell required");
    assert!(shell.starts_with(b"\x7fELF"));
    ceremony::commit(f, PermissionMode::RiskBased, 0);
    let paths = Paths::new(&f.root.path().join("workspace"));
    let command = paths.command();
    paths.pending();
    let (b, prepared) = target::prepare_with_command(f, command.clone(), &shell);
    let original = prepared.observation();
    assert_eq!(b.command(), &command);
    assert_eq!(
        b.command_intent_digest().as_bytes(),
        &command.intent_digest()
    );
    assert_eq!(
        b.approval().normalized_arguments_digest.as_bytes(),
        original.normalized_arguments_digest()
    );
    assert_eq!(
        b.approval().tool_schema_digest.as_bytes(),
        original.schema_digest()
    );
    assert_eq!(
        b.approval().target_identity_digest.as_bytes(),
        original.target_identity()
    );
    assert_eq!(b.approval().target_version, original.target_version());
    assert_eq!(
        b.approval().environment_digest.as_bytes(),
        original.environment_digest()
    );
    assert_eq!(
        b.approval().cwd_identity_digest.as_bytes(),
        original.cwd_identity()
    );
    assert_eq!(
        b.approval().executable_digest.unwrap().as_bytes(),
        original.executable_digest()
    );
    let pending = f
        .store
        .capture_local_command_permission(&b, original)
        .unwrap();
    assert_eq!(pending.state, LocalCommandAttemptState::ApprovalPending);
    assert_eq!(pending.canonical_binding_digest, *b.digest().as_bytes());
    assert_eq!(pending.native_owner_id, *original.owner_id());
    assert_eq!(pending.native_owner_generation, original.owner_generation());
    paths.pending();

    // Actual path mutation after capture, before approval/admission; A stays held.
    paths.replace(&shell);
    paths.pending();
    let snapshot =
        SealedExecutableSnapshot::from_held_file(&File::open(paths.tool()).unwrap()).unwrap();
    let replacement = f
        .store
        .local_permission_preparation()
        .unwrap()
        .prepare_target(b.command().clone(), &f.held, &f.held, snapshot)
        .unwrap();
    let observed = replacement.observation();
    assert_eq!(observed.owner_id(), original.owner_id());
    assert_eq!(observed.owner_generation(), original.owner_generation());
    assert_eq!(
        observed.normalized_arguments_digest(),
        original.normalized_arguments_digest()
    );
    assert_eq!(observed.schema_digest(), original.schema_digest());
    assert_eq!(observed.environment_digest(), original.environment_digest());
    assert_eq!(observed.workspace_identity(), original.workspace_identity());
    assert_eq!(observed.cwd_identity(), original.cwd_identity());
    assert_eq!(observed.target_version(), original.target_version());
    assert_ne!(observed.target_identity(), original.target_identity());
    assert_ne!(observed.executable_digest(), original.executable_digest());
    assert_eq!(
        f.store
            .load_local_command_permission_capture(pending.taskrun_id)
            .unwrap(),
        Some(pending.clone())
    );
    paths.assert_replaced(&shell);
    paths.pending();

    let approval_id = approval::confirm_native_fixture(f, &b);
    paths.pending();
    let receipt = f
        .store
        .admit_local_command_permission(&b, Some(approval_id))
        .unwrap();
    let proof = approval::durable(f, &b, approval_id);
    let approved = f
        .store
        .load_local_command_permission_capture(pending.taskrun_id)
        .unwrap()
        .unwrap();
    let mut expected = pending.clone();
    expected.state = LocalCommandAttemptState::Approved;
    assert_eq!(approved, expected);
    paths.pending();
    // Refusal is at public bind, before replacement spawn or receipt consumption.
    assert!(matches!(
        replacement.bind(b.clone()),
        Err(LinuxCommandError::Unverified)
    ));
    assert_eq!(
        f.store
            .load_local_command_permission_capture(pending.taskrun_id)
            .unwrap(),
        Some(approved.clone())
    );
    assert_eq!(approval::durable(f, &b, approval_id), proof);
    paths.assert_replaced(&shell);
    paths.pending();

    // Compatible retained original uses its genuine receipt and the public GO.
    let area = Area::new(&b);
    area.get().prove_empty().unwrap().revalidate().unwrap();
    let mut child = Child::new(
        prepared
            .bind(b.clone())
            .unwrap()
            .spawn(area.get(), receipt, &[])
            .unwrap(),
    );
    assert!(area.get().is_populated().unwrap());
    assert!(!child.child.was_released());
    assert_eq!(child.child.original_binding(), &b);
    assert_eq!(child.child.observation(), original);
    assert_eq!(
        child.child.area_identity(),
        area.get().identity().to_bytes()
    );
    paths.pending();
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
    assert_eq!(
        child.child.wait_leader(Duration::from_secs(2)).unwrap(),
        LinuxLeaderExitKindV1::Exited { code: 0 }
    );
    let output = child.drain();
    child.evidence(area.get());
    assert_eq!(
        child.child.terminal_evidence().unwrap().leader_exit_kind(),
        LinuxLeaderExitKindV1::Exited { code: 0 }
    );
    paths.effects();
    paths.assert_replaced(&shell);
    let payload = terminal::success(f, b.assignment().taskrun_id);
    let version = payload.expected_version + 1;
    assert!(matches!(
        f.store
            .commit_local_command_permission_terminal(
                payload,
                b.assignment(),
                &b,
                &child.child,
                output,
            )
            .unwrap(),
        CommitResult::Committed { .. }
    ));
    terminal::assert_success(f, b.assignment().taskrun_id, version);
    let completed = f
        .store
        .load_local_command_permission_capture(pending.taskrun_id)
        .unwrap()
        .unwrap();
    expected.state = LocalCommandAttemptState::Completed;
    assert_eq!(completed, expected);
    assert_eq!(approval::durable(f, &b, approval_id), proof);
    let cleanup = f
        .store
        .scan_local_command_terminal_cleanup(None, 8)
        .unwrap();
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0].identity, *b.assignment());
    assert_eq!(cleanup[0].area_identity, area.get().identity().to_bytes());
    assert_eq!(cleanup[0].state, LocalCommandAttemptState::Completed);
    assert_eq!(cleanup[0].exit_code, Some(0));
    child.disarm();
    drop(child);
    area.finish();
    paths.effects();
    paths.assert_replaced(&shell);
    // OwnedFixture closes Store/trust/native handles before disposing fresh RAM.
}
