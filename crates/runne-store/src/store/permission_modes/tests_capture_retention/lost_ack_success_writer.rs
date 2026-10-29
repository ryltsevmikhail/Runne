//! Original native owner: commit while retained, then never send a result ACK.
use super::super::super::{ceremony, fixture, target};
use super::{Context, Intent, Request, deadline, pause, read, write};
use fixture::Fixture;
#[path = "../tests_admitted_retention/approval.rs"]
mod approval;
#[path = "../tests_g2_corrupt_policy/owned.rs"]
mod owned;
#[path = "../tests_terminal_retry_support.rs"]
mod support;
#[path = "../tests_shell_corpus/terminal.rs"]
mod terminal;
use runne_application::{permission_modes::PermissionMode, ports::CommitResult};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use std::{path::Path, time::Duration};

pub(super) fn run(root: &Path, context: &Context) {
    let nested = tempfile::tempdir_in(root).unwrap();
    let f = Fixture::with_root_and_existing_database(nested, context.database());
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let shell = std::fs::read("/bin/sh").unwrap();
    assert!(shell.starts_with(b"\x7fELF"));
    let nonce = uuid::Uuid::from_bytes(context.run);
    let argv = vec![
        "tool".into(),
        "-c".into(),
        format!(
            "printf '%s\\n' '{nonce}' >> terminal-retry-marker; printf retry-out; printf retry-err >&2"
        ),
    ];
    let claim_recorder = super::claim::ClaimRecorder::new(&f.store);
    let command = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
        ".".into(),
        argv,
        vec![],
    )
    .unwrap();
    let (b, prepared, conversation) =
        target::prepare_with_command_recorded(&f, command, &shell, &claim_recorder);
    let claim = claim_recorder.take();
    let observation = prepared.observation();
    let capture = f
        .store
        .capture_local_command_permission(&b, prepared.observation())
        .unwrap();
    assert_eq!(capture.taskrun_id, b.assignment().taskrun_id);
    assert_eq!(capture.attempt_id, b.assignment().attempt_id);
    assert_eq!(capture.fence, b.assignment().fence.0);
    assert_eq!(capture.invocation_id, b.invocation_id());
    assert_eq!(capture.canonical_binding_digest, *b.digest().as_bytes());
    assert_eq!(capture.native_owner_id, *observation.owner_id());
    assert_eq!(
        capture.native_owner_generation,
        observation.owner_generation()
    );
    let approval_id = approval::confirm_native_fixture(&f, &b);
    let receipt = f
        .store
        .admit_local_command_permission(&b, Some(approval_id))
        .unwrap();
    let area = owned::Area::new(&b);
    let mut child = owned::Child::new(
        prepared
            .bind(b.clone())
            .unwrap()
            .spawn(area.get(), receipt, &[])
            .unwrap(),
    );
    f.store
        .release_local_command_permission(
            b.assignment(),
            b.claim_stream_version(),
            &b,
            area.get(),
            &mut child.child,
        )
        .unwrap();
    assert_eq!(
        child.child.wait_leader(Duration::from_secs(2)).unwrap(),
        LinuxLeaderExitKindV1::Exited { code: 0 }
    );
    let output = support::Output::drain(&mut child.child);
    child.evidence(area.get());
    let payload = terminal::success(&f, b.assignment().taskrun_id);
    let original_facts = super::facts::Facts::freeze(
        context,
        &f,
        &b,
        capture.binding_digest,
        &payload,
        area.get(),
        &observation,
        claim,
        conversation,
    )
    .unwrap()
    .encode()
    .unwrap();
    let intent = Intent {
        original_facts,
        trust: super::trust::OriginalTrust::of(&f),
        request: serde_json::to_vec(&Request::of(&payload, context.run)).unwrap(),
        command: *payload.command_id.as_bytes(),
        task: *b.assignment().taskrun_id.as_bytes(),
        attempt: *b.assignment().attempt_id.as_bytes(),
        fingerprint: *payload.command_fingerprint.as_bytes(),
        key: payload.idempotency_key.as_str().into(),
        version: payload.expected_version + 1,
        area: area.get().identity().to_bytes().to_vec(),
        workspace: f.root.path().join("workspace"),
        writer: std::process::id(),
    };
    // Rename publishes the complete original intent before C's independent observation.
    write(root, "intent-staged.json", &intent);
    std::fs::rename(
        root.join("intent-staged.json"),
        root.join("intent-ready.json"),
    )
    .unwrap();
    let until = deadline();
    while !root.join("commit-go.json").exists() {
        pause(until);
    }
    assert_eq!(read::<[u8; 16]>(root, "commit-go.json"), context.run);
    assert_eq!(
        f.store
            .commit_local_command_permission_terminal(
                payload,
                b.assignment(),
                &b,
                &child.child,
                output.exact()
            )
            .unwrap(),
        CommitResult::Committed {
            new_version: intent.version
        }
    );
    terminal::assert_success(&f, b.assignment().taskrun_id, intent.version);
    // Keep native child, Store, root fence and area alive. Only C's independent
    // committed observation permits abrupt abort; no result response is sent.
    while !root.join("abort-go.json").exists() {
        pause(until);
    }
    assert_eq!(read::<[u8; 16]>(root, "abort-go.json"), context.run);
    std::process::abort();
}
