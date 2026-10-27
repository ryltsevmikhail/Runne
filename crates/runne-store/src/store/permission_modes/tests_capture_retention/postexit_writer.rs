use super::{
    approval, ceremony,
    fixture::Fixture,
    metadata::{Area, Capture, Context, Cut},
    observations, paths, target,
};
use crate::{schema, store::LocalCommandAttemptState};
use runne_application::{permission_modes::PermissionMode, project_trust::ProjectTrustPersistence};
use runne_domain::task_run::TaskRunState;
use runne_platform::{
    local_command_linux::{LinuxLeaderExitKindV1, PermissionChildV1},
    process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding},
};
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) fn write_and_abort(root: &Path, context: Context) -> ! {
    write_impl(root, context, false)
}

pub(super) fn write_and_abort_with_request(root: &Path, context: Context) -> ! {
    write_impl(root, context, true)
}

fn write_impl(root: &Path, context: Context, save_request: bool) -> ! {
    context.assert_controller();
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
            "printf once >> effect-marker".into(),
        ],
        &elf,
    );
    assert!(!f.root.path().join("workspace/effect-marker").exists());
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
    paths::write(root, "area.json", &saved);
    if save_request {
        let request = super::invocation_request::RequestRecord::of(&saved, &b);
        paths::write(root, "request.json", &request);
        let reread: super::invocation_request::RequestRecord = paths::read(root, "request.json");
        assert_eq!(reread, request);
    }
    let mut child = OwnedNative::new(
        prepared
            .bind(b.clone())
            .unwrap()
            .spawn(&area, receipt, &[])
            .unwrap(),
    );
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
        assert!(Instant::now() < deadline, "bounded EOF drain");
        std::thread::sleep(Duration::from_millis(5));
    };
    let terminal = child.child.terminal_evidence().unwrap();
    terminal.revalidate_empty_area().unwrap();
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    let marker = std::fs::read(saved.marker(root)).unwrap();
    assert_eq!(marker, b"once");
    observations::attempt(&reader, &saved, "running");
    observations::no_factual_terminal_or_provider(&reader, &saved);
    observations::count(&reader, "taskrun_terminal_settlement_receipts", &saved, 0);
    observations::count(&reader, "taskrun_local_command_stop_receipts", &saved, 0);
    assert_eq!(observations::spent(&reader, &saved), spent);
    assert_eq!(f.trust.load(f.trust_id()).unwrap(), trust);
    let (stream_version, event_ids) = observations::stream(&f.store, &saved, TaskRunState::Running);
    let cut = Cut {
        version: 1,
        role: "writer-cut".into(),
        original: saved.clone(),
        released: child.child.was_released(),
        exit: 0,
        reaped: true,
        stdout_eof: chunk.stdout_eof,
        stderr_eof: chunk.stderr_eof,
        stdout_bytes: chunk.stdout_observed_bytes,
        stderr_bytes: chunk.stderr_observed_bytes,
        terminal_empty: true,
        fresh_empty: true,
        marker,
        spent,
        stream_version,
        event_ids,
    };
    cut.validate(&saved);
    paths::write(root, "cut.json", &cut);
    // No Store terminal write, trust revoke, area removal or destructor before abort.
    // Fixture/Store/trust/native owner/root fence/area/child/empty/terminal stay live.
    std::process::abort()
}

struct OwnedNative<'a> {
    child: PermissionChildV1<'a>,
}
impl<'a> OwnedNative<'a> {
    fn new(child: PermissionChildV1<'a>) -> Self {
        Self { child }
    }
}
impl Drop for OwnedNative<'_> {
    fn drop(&mut self) {
        // Ordinary unwind only. Abrupt failures without the completed cut never pass.
        let stop = self.child.terminate_area(Duration::from_millis(20));
        let reap = self.child.reap_after_stop(Duration::from_secs(2));
        eprintln!("R05_POSTEXIT_FAILURE_NATIVE stop={stop:?} reap={reap:?}");
    }
}
