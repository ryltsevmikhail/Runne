use super::{
    metadata::{Area, Context, Cut, ResultRecord},
    observations, paths, receipts,
};
use crate::{
    ProjectTrustStore, execution_node,
    schema::{self, ConnectionMode},
    store::{LocalCommandAttemptState, StoreTransaction},
};
use runne_application::{
    ports::{EventStore, RuntimeAuthorityId},
    project_trust::{ProjectTrustPersistence, ProjectTrustProjectId},
};
use runne_domain::{
    id::ProjectId,
    task_run::{TaskRunEvent, TaskRunState},
};
use runne_platform::process_managed_area::LinuxManagedAreaRoot;
use std::{path::Path, sync::Arc};

pub(super) fn recover(root: &Path, context: &Context) {
    recover_impl(root, context, false, false);
}

pub(super) fn recover_with_restart_refusal(root: &Path, context: &Context) {
    recover_impl(root, context, true, false);
}

pub(super) fn recover_with_invocation_refusal(root: &Path, context: &Context) {
    recover_impl(root, context, false, true);
}
fn recover_impl(root: &Path, context: &Context, refuse_restart: bool, refuse_invocation: bool) {
    context.assert_controller();
    let saved: Area = paths::read(root, "area.json");
    saved.validate(root, context);
    assert_ne!(saved.writer_pid, std::process::id());
    let cut: Cut = paths::read(root, "cut.json");
    cut.validate(&saved);
    let daemon = saved.daemon(root);
    let db = daemon.join("store.sqlite");
    paths::regular(&db);
    // Opening trust must never manufacture a replacement sidecar.
    paths::regular(&daemon.join("trust.sqlite.project-trust"));
    let writer = observations::reopen(root, &saved, ConnectionMode::ValidatedReopen);
    let reader = observations::reader(root, &saved);
    let epoch = schema::next_launch_generation(&writer).unwrap();
    assert!(epoch > saved.epoch);
    let store = StoreTransaction::open_with_connections(
        db.to_str().unwrap(),
        writer,
        reader,
        RuntimeAuthorityId(hex::encode(saved.authority)),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let trust =
        Arc::new(ProjectTrustStore::open(&daemon.join("trust.sqlite"), saved.authority).unwrap());
    let project: ProjectId = saved.project.parse().unwrap();
    let project = ProjectTrustProjectId::from_bytes(project.into_bytes());
    let original_trust = saved.trust_record();
    let retained = trust.load(project).unwrap();
    assert_eq!(retained, original_trust);
    assert_eq!(retained.token(), original_trust.token());
    {
        let writer = store.inner.writer.lock().unwrap();
        execution_node::register_local_linux_node(
            &writer,
            saved.authority,
            epoch,
            execution_node::LinuxNodeDescriptor { capacity: 1 },
            30,
        )
        .unwrap();
        execution_node::heartbeat_local_linux_node(&writer, saved.authority, epoch, 30).unwrap();
    }
    let candidates = store.scan_local_command_recovery(None, 128).unwrap();
    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    assert_eq!(candidate.identity, saved.identity());
    assert_eq!(candidate.area_identity, saved.area);
    assert_eq!(candidate.state, LocalCommandAttemptState::Running);
    assert_eq!(candidate.exit_code, None);
    observations::capture(&store, &saved, LocalCommandAttemptState::Running);
    assert_eq!(
        observations::stream(&store, &saved, TaskRunState::Running),
        (cut.stream_version, cut.event_ids.clone())
    );
    {
        let fresh = observations::reader(root, &saved);
        observations::attempt(&fresh, &saved, "running");
        assert_eq!(observations::spent(&fresh, &saved), cut.spent);
        observations::no_factual_terminal_or_provider(&fresh, &saved);
        observations::count(&fresh, "taskrun_terminal_settlement_receipts", &saved, 0);
        observations::count(&fresh, "taskrun_local_command_stop_receipts", &saved, 0);
    }
    assert_eq!(std::fs::read(saved.marker(root)).unwrap(), b"once");
    // Settlement remains ownerless; a selected refusal suffix may prepare a fresh target.
    let managed = LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    let area = managed
        .reopen_area(saved.area_identity(), saved.binding())
        .unwrap();
    assert_eq!(area.identity().to_bytes().as_slice(), saved.area);
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    store
        .authorize_local_command_recovery(candidate, &candidate.identity.node_id, epoch)
        .unwrap();
    store
        .settle_local_command_outcome_unknown_recovery(
            candidate,
            &candidate.identity.node_id,
            epoch,
            empty,
        )
        .unwrap();
    let settled_stream = observations::stream(&store, &saved, TaskRunState::Unrecoverable);
    assert_eq!(settled_stream.0, cut.stream_version + 2);
    assert_eq!(settled_stream.1.len(), cut.event_ids.len() + 2);
    assert_eq!(
        &settled_stream.1[..cut.event_ids.len()],
        cut.event_ids.as_slice()
    );
    let stream = store.load_task_run(candidate.identity.taskrun_id).unwrap();
    assert!(matches!(
        stream.events[cut.event_ids.len()].payload(),
        TaskRunEvent::ReconciliationStarted
    ));
    assert!(matches!(
        stream.events[cut.event_ids.len() + 1].payload(),
        TaskRunEvent::Unrecoverable
    ));
    observations::capture(&store, &saved, LocalCommandAttemptState::OutcomeUnknown);
    let head = settled_stream.1.last().unwrap();
    let (original_receipts, original_attempt) = {
        let fresh = observations::reader(root, &saved);
        let r = receipts::observe(&fresh, &saved, epoch, head, settled_stream.0);
        let a = observations::attempt(&fresh, &saved, "outcome_unknown");
        assert_eq!(observations::spent(&fresh, &saved), cut.spent);
        (r, a)
    };
    assert_eq!(trust.load(project).unwrap(), original_trust);
    assert_eq!(trust.load(project).unwrap().token(), original_trust.token());
    assert_eq!(std::fs::read(saved.marker(root)).unwrap(), b"once");
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    // The original Running candidate is intentionally reused; settlement rereads DB.
    store
        .settle_local_command_outcome_unknown_recovery(
            candidate,
            &candidate.identity.node_id,
            epoch,
            empty,
        )
        .unwrap();
    assert_eq!(
        observations::stream(&store, &saved, TaskRunState::Unrecoverable),
        settled_stream
    );
    if refuse_invocation {
        super::invocation_refusal::assert_refused(
            root,
            &saved,
            &store,
            trust.clone(),
            settled_stream.0,
        );
    }
    if refuse_restart {
        super::restart_refusal::assert_refused(&store, &saved, settled_stream.0);
    }
    {
        let fresh = observations::reader(root, &saved);
        assert_eq!(
            receipts::observe(&fresh, &saved, epoch, head, settled_stream.0),
            original_receipts
        );
        assert_eq!(
            observations::attempt(&fresh, &saved, "outcome_unknown"),
            original_attempt
        );
        assert_eq!(observations::spent(&fresh, &saved), cut.spent);
    }
    assert_eq!(
        observations::stream(&store, &saved, TaskRunState::Unrecoverable),
        settled_stream
    );
    let rescanned = store.scan_local_command_recovery(None, 128).unwrap();
    assert_eq!(rescanned.len(), 1);
    assert_eq!(rescanned[0].identity, candidate.identity);
    assert_eq!(rescanned[0].area_identity, saved.area);
    assert_eq!(rescanned[0].state, LocalCommandAttemptState::OutcomeUnknown);
    assert_eq!(rescanned[0].exit_code, None);
    observations::capture(&store, &saved, LocalCommandAttemptState::OutcomeUnknown);
    let retained = trust.load(project).unwrap();
    assert_eq!(retained, original_trust);
    assert_eq!(retained.token(), original_trust.token());
    assert_eq!(std::fs::read(saved.marker(root)).unwrap(), b"once");
    context.assert_controller();
    area.prove_empty().unwrap().revalidate().unwrap();
    // Recovery is the exclusive successful remover of the original held area.
    area.remove_empty().unwrap();
    assert!(managed.area_is_absent(&saved.area_identity()).unwrap());
    paths::write(
        root,
        "result.json",
        &ResultRecord {
            version: 1,
            role: "recovery".into(),
            cut,
            recovery_pid: std::process::id(),
            removed: true,
        },
    );
}
