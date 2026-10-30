//! Supporting bounded R08 corpus only; guest-only, logical approval, no daemon.
#[path = "tests_admitted_retention/approval.rs"]
mod approval;
#[path = "tests_shell_corpus/corpus.rs"]
mod corpus;
#[path = "tests_shell_corpus/owned.rs"]
mod owned;
#[path = "tests_shell_corpus/terminal.rs"]
mod terminal;

use super::{ceremony, fixture, target};
use crate::store::{LocalCommandAttemptState, LocalCommandPermissionTerminalOutputV1};
use corpus::Corpus;
use fixture::Fixture;
use owned::{Area, Child};
use runne_application::{permission_modes::PermissionMode, ports::CommitResult};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use std::time::{Duration, Instant};

#[test]
fn installed_shell_preserves_bound_corpus_through_public_go_and_terminal() {
    // This must later run only in a separately reviewed fresh disposable guest.
    let elf = std::fs::read("/bin/sh").expect("R08/NOTRUN: installed /bin/sh required; no install");
    assert!(
        elf.starts_with(b"\x7fELF"),
        "R08/NOTRUN: installed shell must be ELF"
    );
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let corpus = Corpus::new(&f.root.path().join("workspace"));
    let command = corpus.command();
    Corpus::assert_intent(&command);
    corpus.assert_pending();
    let (b, prepared) = target::prepare_with_command(&f, command.clone(), &elf);
    assert_eq!(b.command(), &command);
    Corpus::assert_intent(b.command());
    assert_eq!(
        b.command_intent_digest().as_bytes(),
        &command.intent_digest()
    );
    assert_eq!(
        b.approval().environment_digest.as_bytes(),
        prepared.observation().environment_digest()
    );
    assert_eq!(
        b.approval().cwd_identity_digest.as_bytes(),
        prepared.observation().cwd_identity()
    );
    corpus.assert_pending();
    let capture = f
        .store
        .capture_local_command_permission(&b, prepared.observation())
        .unwrap();
    assert_eq!(capture.state, LocalCommandAttemptState::ApprovalPending);
    assert_eq!(capture.canonical_binding_digest, *b.digest().as_bytes());
    corpus.assert_pending();
    let approval_id = approval::confirm_native_fixture(&f, &b);
    corpus.assert_pending();
    let receipt = f
        .store
        .admit_local_command_permission(&b, Some(approval_id))
        .unwrap();
    let _original_logical_proof = approval::durable(&f, &b, approval_id);
    corpus.assert_pending();
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
    corpus.assert_pending();
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
        assert!(Instant::now() < deadline, "bounded complete EOF drain");
        std::thread::sleep(Duration::from_millis(5));
    };
    // Wait only on this owned area; an unproven empty area cannot settle.
    let empty_deadline = Instant::now() + Duration::from_secs(2);
    while area.get().is_populated().unwrap() {
        assert!(
            Instant::now() < empty_deadline,
            "bounded owned-area empty wait"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    {
        // This evidence requires the actual waitpid cache (reap), not a claimed exit.
        let evidence = child.child.terminal_evidence().unwrap();
        assert_eq!(
            evidence.leader_exit_kind(),
            LinuxLeaderExitKindV1::Exited { code: 0 }
        );
        assert_eq!(evidence.area_identity(), &area.get().identity().to_bytes());
        evidence.revalidate_empty_area().unwrap();
    }
    area.get().prove_empty().unwrap().revalidate().unwrap();
    corpus.assert_effects();
    let output = LocalCommandPermissionTerminalOutputV1::new(
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
    let payload = terminal::success(&f, b.assignment().taskrun_id);
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
    terminal::assert_success(&f, b.assignment().taskrun_id, version);
    let cleanup = f
        .store
        .scan_local_command_terminal_cleanup(None, 8)
        .unwrap();
    assert_eq!(cleanup[0].identity, *b.assignment());
    assert_eq!(cleanup[0].area_identity, area.get().identity().to_bytes());
    corpus.assert_effects();
    area.get().prove_empty().unwrap().revalidate().unwrap();
    child.verified_terminal();
    drop(child);
    area.finish();
    corpus.assert_effects();
}
