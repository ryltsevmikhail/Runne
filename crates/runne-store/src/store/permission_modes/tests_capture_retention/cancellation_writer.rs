use super::{
    approval, attempt,
    budget::Deadline,
    ceremony,
    fixture::Fixture,
    metadata::{Area, Capture, Context},
    native::{self, OwnedNative},
    observations, paths, records,
    records::Cut,
    target,
};
use crate::{schema, store::LocalCommandAttemptState};
use runne_application::{permission_modes::PermissionMode, project_trust::ProjectTrustPersistence};
use runne_domain::task_run::TaskRunState;
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding};
use std::path::Path;
use std::time::Duration;

pub(super) fn write_and_abort(root: &Path, context: Context, deadline: Deadline) -> ! {
    context.assert_controller();
    deadline.check();
    let nested = tempfile::tempdir_in(root).unwrap();
    let f = Fixture::with_root(nested);
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let elf = std::fs::read("/bin/sh").expect("installed guest shell ELF");
    assert!(elf.starts_with(b"\x7fELF"));
    let (b, prepared) = target::prepare_with_executable(
        &f,
        vec![
            "tool".into(),
            "-c".into(),
            "printf ready; while [ ! -f proceed ]; do :; done; printf once >> effect-marker".into(),
        ],
        &elf,
    );

    let captured = f
        .store
        .capture_local_command_permission(&b, prepared.observation())
        .unwrap();
    let approval_id = approval::confirm_native_fixture(&f, &b);
    let receipt = f
        .store
        .admit_local_command_permission(&b, Some(approval_id))
        .unwrap();
    let id = b.assignment();
    let managed = LinuxManagedAreaRoot::open_current_cgroup().expect("delegated guest root");
    let area = managed
        .create_area(
            ManagedAreaBinding::new(
                *id.taskrun_id.as_bytes(),
                *id.attempt_id.as_bytes(),
                *b.invocation_id().as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
    let trust = f.trust.load(f.trust_id()).unwrap();
    let (authority, lineage) = {
        let writer = f.store.inner.writer.lock().unwrap();
        (
            schema::read_authority_id(&writer).unwrap().unwrap(),
            schema::read_event_log_lineage_id(&writer).unwrap().unwrap(),
        )
    };
    let saved = Area {
        version: 1,
        role: "writer".into(),
        context,
        writer_pid: std::process::id(),
        nested: f.root.path().file_name().unwrap().to_str().unwrap().into(),
        authority,
        lineage: lineage.to_string(),
        project: f.project.to_string(),
        workspace: f.scope.workspace_id.to_string(),
        principal: f.principal.as_str().into(),
        node: id.node_id.0.clone(),
        epoch: id.node_epoch,
        area: area.identity().to_bytes().to_vec(),
        command_digest: *b.command_intent_digest().as_bytes(),
        capture: Capture::of(&captured),
        trust_status: "Trusted".into(),
        trust_epoch: trust.instance_epoch,
        trust_revision: trust.revision,
        trust_mask: trust.managed_deny_mask,
    };
    assert_eq!(trust, saved.trust_record());
    saved.validate(root, &saved.context);
    assert_eq!(saved.identity(), *id);
    // An immutable, synced original identity must exist BEFORE any native spawn.
    records::absent(root, &saved);
    paths::write(root, "area.json", &saved);
    deadline.check();
    let mut child = OwnedNative {
        child: prepared
            .bind(b.clone())
            .unwrap()
            .spawn(&area, receipt, &[])
            .unwrap(),
        deadline,
    };
    assert!(area.is_populated().unwrap());
    assert!(!child.child.was_released());
    f.store
        .release_local_command_permission(id, b.claim_stream_version(), &b, &area, &mut child.child)
        .unwrap();
    assert!(child.child.was_released());
    let reader = observations::reader(root, &saved);
    let spent = observations::spent(&reader, &saved);
    observations::attempt(&reader, &saved, "running");
    observations::capture(&f.store, &saved, LocalCommandAttemptState::Running);
    let mut stdout = Vec::new();
    native::output(&mut child, &mut stdout, false);
    assert!(area.is_populated().unwrap());
    records::absent(root, &saved);
    let (command, key, expected_version, stream_version, event_ids, rows) =
        native::cancel(&f, &saved, root);
    assert_eq!(
        f.store
            .local_command_permission_stop_reason(id, &b)
            .unwrap(),
        Some(1)
    );
    observations::attempt(&observations::reader(root, &saved), &saved, "running");
    let initial_attempt = attempt::observe(&observations::reader(root, &saved), &saved, "running");
    deadline.check();
    child
        .child
        .terminate_area(Duration::from_millis(20))
        .unwrap();
    child
        .child
        .reap_after_stop(deadline.phase().remaining())
        .unwrap();
    let exit = child
        .child
        .try_wait()
        .unwrap()
        .expect("cached direct owned waitpid result");
    native::output(&mut child, &mut stdout, true);
    let terminal = child.child.terminal_evidence().unwrap();
    terminal.revalidate_empty_area().unwrap();
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    assert_eq!(terminal.leader_exit_kind(), exit);
    assert!(terminal.output_matches(b"ready", b"", 5, 0, false, false, true, true, false));
    records::absent(root, &saved);
    observations::attempt(&reader, &saved, "running");
    observations::no_factual_terminal_or_provider(&reader, &saved);
    observations::count(&reader, "taskrun_terminal_settlement_receipts", &saved, 0);
    observations::count(&reader, "taskrun_local_command_stop_receipts", &saved, 0);
    assert_eq!(observations::spent(&reader, &saved), spent);
    assert_eq!(f.trust.load(f.trust_id()).unwrap(), trust);
    assert_eq!(
        observations::stream(&f.store, &saved, TaskRunState::Cancelling),
        (stream_version, event_ids.clone())
    );
    let fresh = observations::reader(root, &saved);
    assert_eq!(
        receipts_rows(&fresh, &saved, &event_ids, stream_version),
        rows
    );
    assert_eq!(attempt::observe(&fresh, &saved, "running"), initial_attempt);
    observations::capture(&f.store, &saved, LocalCommandAttemptState::Running);
    deadline.check();
    let cut = Cut {
        version: 1,
        role: "writer-cut".into(),
        original: saved.clone(),
        released: child.child.was_released(),
        exit: exit.into(),
        reaped: true,
        stdout_eof: true,
        stderr_eof: true,
        stdout_bytes: 5,
        stderr_bytes: 0,
        terminal_empty: true,
        fresh_empty: true,
        stdout,
        stderr: vec![],
        stop: rows.stop,
        occupation: rows.occupation,
        attempt: initial_attempt,
        command,
        key,
        expected_version,
        outcome: "TaskRunCancellationRequested".into(),
        spent,
        stream_version,
        event_ids,
    };
    cut.validate(&saved);
    paths::write(root, "cut.json", &cut);
    // No Store terminal write, trust revoke, area removal or destructor before abort.
    // Fixture/Store/trust/native owner/root fence/area/child/empty/terminal stay live.
    records::absent(root, &saved);
    deadline.check();
    std::process::abort()
}

fn receipts_rows(
    c: &rusqlite::Connection,
    a: &Area,
    ids: &[Vec<u8>],
    version: u64,
) -> super::receipts::Rows {
    super::receipts::observe(c, a, ids.last().unwrap(), version, None)
}
