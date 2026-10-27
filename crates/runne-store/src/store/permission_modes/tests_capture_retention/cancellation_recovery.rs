use super::{
    attempt, bootstrap,
    budget::Deadline,
    metadata::{Area, Context},
    native, observations, paths, receipts,
    records::{self, Cut, ResultRecord},
};
use crate::{
    ProjectTrustStore,
    store::taskrun_local_command::LocalCommandRecoveryCandidate,
    store::{LocalCommandAttemptState, StoreTransaction},
};
use runne_application::ports::EventStore;
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use runne_platform::process_managed_area::LinuxManagedAreaRoot;
use std::path::Path;

type Snapshot = (receipts::Rows, attempt::Attempt, (u64, Vec<Vec<u8>>));
fn checkpoint(
    root: &Path,
    a: &Area,
    cut: &Cut,
    store: &StoreTransaction,
    trust: &ProjectTrustStore,
    local: LocalCommandAttemptState,
    state: &str,
    settled: Option<&(u64, Vec<Vec<u8>>)>,
) -> Snapshot {
    let stream = observations::stream(
        store,
        a,
        if settled.is_some() {
            TaskRunState::Cancelled
        } else {
            TaskRunState::Cancelling
        },
    );
    assert_eq!(
        &stream,
        settled.unwrap_or(&(cut.stream_version, cut.event_ids.clone()))
    );
    observations::capture(store, a, local);
    let fresh = observations::reader(root, a);
    let rows = receipts::observe(
        &fresh,
        a,
        cut.event_ids.last().unwrap(),
        cut.stream_version,
        settled.map(|s| (s.1.last().unwrap().as_slice(), s.0)),
    );
    assert_eq!(rows.stop, cut.stop);
    let mut expected = cut.occupation.clone();
    if let Some(s) = settled {
        expected.6 = "released".into();
        expected.8 = Some(s.1.last().unwrap().clone());
    }
    assert_eq!(rows.occupation, expected);
    assert_eq!(observations::spent(&fresh, a), cut.spent);
    let attempt = attempt::observe(&fresh, a, state);
    attempt.same_immutable(&cut.attempt);
    bootstrap::trust(trust, a);
    records::absent(root, a);
    (rows, attempt, stream)
}
fn authorize(store: &StoreTransaction, c: &LocalCommandRecoveryCandidate, epoch: u64) {
    store
        .authorize_local_command_recovery(c, &c.identity.node_id, epoch)
        .unwrap();
}
fn scans(store: &StoreTransaction, c: &LocalCommandRecoveryCandidate) {
    assert!(
        store
            .scan_local_command_recovery(None, 128)
            .unwrap()
            .is_empty()
    );
    let cleanup = store
        .scan_local_command_terminal_cleanup(None, 128)
        .unwrap();
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0].identity, c.identity);
    assert_eq!(cleanup[0].area_identity, c.area_identity);
    assert_eq!(cleanup[0].state, LocalCommandAttemptState::Cancelled);
    assert_eq!(cleanup[0].exit_code, None);
}
pub(super) fn recover(root: &Path, context: &Context, deadline: Deadline) {
    deadline.check();
    context.assert_controller();
    let saved: Area = paths::read(root, "area.json");
    saved.validate(root, context);
    assert_ne!(saved.writer_pid, std::process::id());
    let cut: Cut = paths::read(root, "cut.json");
    cut.validate(&saved);
    let (store, trust, epoch) = bootstrap::open(root, &saved);
    deadline.check();
    let candidates = store.scan_local_command_recovery(None, 128).unwrap();
    assert_eq!(candidates.len(), 1);
    // Keep this ORIGINAL Running snapshot unchanged through both later replays.
    let candidate = candidates.into_iter().next().unwrap();
    assert_eq!(candidate.identity, saved.identity());
    assert_eq!(candidate.area_identity, saved.area);
    assert_eq!(candidate.state, LocalCommandAttemptState::Running);
    assert_eq!(candidate.exit_code, None);
    assert!(
        store
            .scan_local_command_terminal_cleanup(None, 128)
            .unwrap()
            .is_empty()
    );
    let before = checkpoint(
        root,
        &saved,
        &cut,
        &store,
        &trust,
        LocalCommandAttemptState::Running,
        "running",
        None,
    );
    assert_eq!(before.1, cut.attempt);
    let cancelled = store.load_task_run(candidate.identity.taskrun_id).unwrap();
    let anchor = cancelled.events.last().unwrap();
    assert!(matches!(
        anchor.payload(),
        TaskRunEvent::CancellationRequested
    ));
    assert_eq!(anchor.command_id().to_string(), cut.command);
    assert_eq!(anchor.idempotency_key(), &super::fixture::key(&cut.key));
    // Ownerless bootstrap: no Fixture, permission owner, native spawn or GO here.
    let managed = LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    let area = managed
        .reopen_area(saved.area_identity(), saved.binding())
        .unwrap();
    assert_eq!(area.identity().to_bytes().as_slice(), saved.area);
    area.prove_empty().unwrap().revalidate().unwrap();
    authorize(&store, &candidate, epoch);
    native::proven(&store, &saved);
    deadline.check();
    store
        .request_local_command_stop_recovery(&candidate, &candidate.identity.node_id, epoch)
        .unwrap();
    checkpoint(
        root,
        &saved,
        &cut,
        &store,
        &trust,
        LocalCommandAttemptState::CancelRequested,
        "cancel_requested",
        None,
    );
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    store
        .confirm_local_command_stopped_recovery(
            &candidate,
            &candidate.identity.node_id,
            epoch,
            empty,
        )
        .unwrap();
    checkpoint(
        root,
        &saved,
        &cut,
        &store,
        &trust,
        LocalCommandAttemptState::Cancelled,
        "cancelled",
        None,
    );
    deadline.check();
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &candidate.identity.node_id,
            epoch,
            empty,
        )
        .unwrap();
    let settled = observations::stream(&store, &saved, TaskRunState::Cancelled);
    assert_eq!(settled.0, cut.stream_version + 1);
    assert_eq!(settled.1.len(), cut.event_ids.len() + 1);
    assert_eq!(&settled.1[..cut.event_ids.len()], cut.event_ids.as_slice());
    let loaded = store.load_task_run(candidate.identity.taskrun_id).unwrap();
    assert!(matches!(
        loaded.events[cut.event_ids.len()].payload(),
        TaskRunEvent::CancellationCompleted
    ));
    assert!(matches!(
        loaded.events[cut.event_ids.len() - 1].payload(),
        TaskRunEvent::CancellationRequested
    ));
    let original = checkpoint(
        root,
        &saved,
        &cut,
        &store,
        &trust,
        LocalCommandAttemptState::Cancelled,
        "cancelled",
        Some(&settled),
    );
    scans(&store, &candidate);
    // Settled API returns before empty-check: explicitly validate fresh proof OUTSIDE it.
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    deadline.check();
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &candidate.identity.node_id,
            epoch,
            empty,
        )
        .unwrap();
    assert_eq!(
        checkpoint(
            root,
            &saved,
            &cut,
            &store,
            &trust,
            LocalCommandAttemptState::Cancelled,
            "cancelled",
            Some(&settled)
        ),
        original
    );
    scans(&store, &candidate);
    drop(store);
    drop(trust);
    deadline.check();
    let (store, trust, next_epoch) = bootstrap::open(root, &saved);
    assert!(next_epoch > epoch);
    authorize(&store, &candidate, next_epoch);
    assert_eq!(
        checkpoint(
            root,
            &saved,
            &cut,
            &store,
            &trust,
            LocalCommandAttemptState::Cancelled,
            "cancelled",
            Some(&settled)
        ),
        original
    );
    let empty = area.prove_empty().unwrap();
    empty.revalidate().unwrap();
    deadline.check();
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &candidate.identity.node_id,
            next_epoch,
            empty,
        )
        .unwrap();
    assert_eq!(
        checkpoint(
            root,
            &saved,
            &cut,
            &store,
            &trust,
            LocalCommandAttemptState::Cancelled,
            "cancelled",
            Some(&settled)
        ),
        original
    );
    scans(&store, &candidate);
    assert_eq!(candidate.state, LocalCommandAttemptState::Running);
    assert_eq!(candidate.exit_code, None);
    context.assert_controller();
    deadline.check();
    records::absent(root, &saved);
    area.prove_empty().unwrap().revalidate().unwrap();
    // Exclusive recovery is the sole successful original-area remover.
    area.remove_empty().unwrap();
    assert!(managed.area_is_absent(&saved.area_identity()).unwrap());
    records::absent(root, &saved);
    deadline.check();
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
    deadline.check();
}
