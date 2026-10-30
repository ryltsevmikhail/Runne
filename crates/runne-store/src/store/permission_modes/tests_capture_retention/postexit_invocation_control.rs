//! Separate real capture control; public scanner/service prove never dispatched.
use super::{ceremony, control_reopen, fixture, invocation_rows::Rows, target};
use crate::{schema, store::LocalCommandAttemptState};
use runne_application::{permission_modes::PermissionMode, ports::*, service::TaskRunService};
use runne_domain::{
    event::Actor,
    task_run::{TaskRun, TaskRunEvent, TaskRunLocalCommand, TaskRunState},
};
use std::path::Path;

pub(super) fn capture_and_settle(command: TaskRunLocalCommand, executable: &[u8]) {
    let mut pending = PendingFixture(Some(fixture::Fixture::new()));
    let f = pending.0.as_ref().unwrap();
    ceremony::commit(f, PermissionMode::RiskBased, 0);
    let (binding, prepared) = target::prepare_with_command(f, command.clone(), executable);
    assert_eq!(binding.command(), &command);
    let observed = prepared.observation();
    let captured = f
        .store
        .capture_local_command_permission(&binding, observed)
        .unwrap();
    assert_eq!(captured.state, LocalCommandAttemptState::ApprovalPending);
    assert_eq!(
        captured.canonical_binding_digest,
        *binding.digest().as_bytes()
    );
    assert_eq!(captured.native_owner_id, *observed.owner_id());
    assert_eq!(
        captured.native_owner_generation,
        observed.owner_generation()
    );
    let id = binding.assignment().clone();
    let version = binding.claim_stream_version();
    let db = f.root.path().join("runtime/daemon/store.sqlite");
    let marker = f.root.path().join("workspace/effect-marker");
    assert!(!marker.exists());
    assert_eq!(
        f.store
            .load_local_command_permission_capture(id.taskrun_id)
            .unwrap()
            .unwrap(),
        captured
    );
    let (authority, lineage, initial_rows) = {
        let c = f.store.inner.reader.lock().unwrap();
        let rows = Rows::read(&c, id.taskrun_id);
        rows.count("x2_permission_bindings", 1);
        rows.no_effect_evidence();
        let state: (String, Option<Vec<u8>>, Option<Vec<u8>>) = c.query_row(
            "SELECT state,managed_area_identity,approval_id FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [id.taskrun_id.as_bytes()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(state, ("approval_pending".into(), None, None));
        (
            schema::read_authority_id(&c).unwrap().unwrap(),
            schema::read_event_log_lineage_id(&c).unwrap().unwrap(),
            rows,
        )
    };
    let principal = f.principal.clone();
    let runtime = f.scope.runtime_authority_id.clone();
    drop(prepared);
    drop(binding);
    let fixture::Fixture {
        root,
        store,
        trust,
        native,
        held,
        ..
    } = pending.0.take().unwrap();
    let mut retained_root = RetainedRoot(Some(root));
    drop(store);
    drop(trust);
    drop(native);
    drop(held);
    let owned_path = retained_root.0.as_ref().unwrap().path().to_path_buf();
    {
        let (store, node, epoch) = control_reopen::store(&db, authority, lineage, id.node_epoch);
        let page = store
            .scan_no_effect_assignments(
                TaskRunNoEffectScanRequest::new(None, 1, node, epoch).unwrap(),
            )
            .unwrap();
        assert!(page.reached_end);
        assert_eq!(page.next_cursor, Some(id.taskrun_id));
        assert_eq!(page.candidates.len(), 1);
        let candidate = page.candidates.into_iter().next().unwrap();
        assert_eq!(candidate.identity, id);
        assert_eq!(candidate.current_version, version);
        let service = TaskRunService::new(store.clone(), store.clone(), store.clone(), runtime);
        let context = ApplicationCommandContext {
            command_id: fixture::command_id(),
            idempotency_key: fixture::key("postexit-invocation-control-no-effect"),
            principal_id: PrincipalId(principal.as_str().into()),
            actor: Actor::new("postexit-control-recovery-test").unwrap(),
        };
        let TaskRunNoEffectReleaseResult::Released(receipt) = service
            .settle_taskrun_no_effect(&context, candidate, &store)
            .unwrap()
        else {
            panic!("fresh control release must commit")
        };
        assert_eq!(receipt.taskrun_id, id.taskrun_id);
        assert_eq!(receipt.attempt_id, id.attempt_id);
        assert_eq!(receipt.fence, id.fence);
        assert_eq!(receipt.new_version, version + 1);
        let stream = store.load_task_run(id.taskrun_id).unwrap();
        let task = TaskRun::replay(&stream.events).unwrap();
        assert_eq!(task.state(), TaskRunState::Failed);
        assert!(task.active_attempt().is_none());
        assert_eq!(stream.current_version, receipt.new_version);
        assert_eq!(stream.last_event_id, Some(receipt.failure_event_id));
        assert!(
            matches!(stream.events.last().unwrap().payload(), TaskRunEvent::TaskRunFailed { reason } if reason == "dispatch_not_started")
        );
        let retained = store
            .load_local_command_permission_capture(id.taskrun_id)
            .unwrap()
            .unwrap();
        let mut expected = captured.clone();
        expected.state = LocalCommandAttemptState::NoEffectTerminal;
        assert_eq!(retained, expected);
        let c = control_reopen::connection(&db, authority, lineage, schema::ConnectionMode::Reader);
        let rows = Rows::read(&c, id.taskrun_id);
        rows.no_effect_evidence();
        rows.count("x2_permission_bindings", 1);
        rows.count("taskrun_no_effect_release_receipts", 1);
        for table in [
            "x2_permission_bindings",
            "taskrun_local_permission_routes",
            "taskrun_assignments",
            "taskrun_claim_receipts",
        ] {
            initial_rows.assert_same_table(&rows, table);
        }
        let released: (String, Option<Vec<u8>>) = c.query_row(
            "SELECT state,release_event_id FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
            [id.taskrun_id.as_bytes()], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(
            released,
            (
                "released".into(),
                Some(receipt.failure_event_id.as_bytes().to_vec())
            )
        );
        let terminal: (String, Option<Vec<u8>>, Option<i32>) = c.query_row(
            "SELECT state,managed_area_identity,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [id.taskrun_id.as_bytes()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(terminal, ("no_effect_terminal".into(), None, None));
        assert!(!marker.exists());
    }
    retained_root.0.take().unwrap().close().unwrap();
    assert!(!Path::new(&owned_path).exists());
}

// Failure retains only this control's owned evidence; no area/child is created.
struct PendingFixture(Option<fixture::Fixture>);
impl Drop for PendingFixture {
    fn drop(&mut self) {
        if let Some(fixture::Fixture { root, .. }) = self.0.take() {
            let _ = root.keep();
        }
    }
}
struct RetainedRoot(Option<tempfile::TempDir>);
impl Drop for RetainedRoot {
    fn drop(&mut self) {
        if let Some(root) = self.0.take() {
            let _ = root.keep();
        }
    }
}
