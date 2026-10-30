//! Ownerless R: durable uncertainty barrier before any physical live-orphan stop.
use super::{
    bootstrap, chain, checkpoint,
    context::CaseContext,
    held_area::HeldAreaReader,
    helper_failure::require,
    orphan,
    record_protocol::Name,
    record_publication,
    recovery_result::{Branch, ResultRecord},
};
use crate::store::{
    LocalCommandAttemptState, StoreTransaction,
    taskrun_local_command::LocalCommandRecoveryCandidate,
};
use runne_application::ports::EventStore;
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use runne_platform::process_managed_area::LinuxManagedAreaRoot;
use std::time::Duration;

fn authorize(store: &StoreTransaction, candidate: &LocalCommandRecoveryCandidate, epoch: u64) {
    store
        .authorize_local_command_recovery(candidate, &candidate.identity.node_id, epoch)
        .unwrap();
}
fn retained(store: &StoreTransaction, candidate: &LocalCommandRecoveryCandidate) {
    let values = store.scan_local_command_recovery(None, 128).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].identity, candidate.identity);
    assert_eq!(values[0].area_identity, candidate.area_identity);
    assert_eq!(values[0].state, LocalCommandAttemptState::OutcomeUnknown);
    assert_eq!(values[0].exit_code, None);
    assert!(
        store
            .scan_local_command_terminal_cleanup(None, 128)
            .unwrap()
            .is_empty()
    );
}

pub(super) fn run(context: &CaseContext) {
    context.check_child();
    let chain = chain::read(context);
    let (_, ack_digest, _, after_digest) = chain::acknowledged(context, &chain);
    let saved = &chain.area;
    let cut = &chain.cut;
    assert_ne!(saved.writer_pid, std::process::id());
    let (store, trust, epoch) = bootstrap::open(context, saved);
    let values = store.scan_local_command_recovery(None, 128).unwrap();
    assert_eq!(values.len(), 1);
    let candidate = values.into_iter().next().unwrap();
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
    assert_eq!(
        checkpoint::before_settle(
            context,
            saved,
            cut,
            &store,
            &trust,
            LocalCommandAttemptState::Running,
            "running"
        ),
        cut.durable.attempt
    );
    let managed = LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    let held = HeldAreaReader::reopen(context, &managed, &saved.area_identity(), saved.binding());
    let live_entry = held.area().is_populated().unwrap();
    if live_entry {
        orphan::observe(context, saved, &held, &cut.live.association);
    }
    authorize(&store, &candidate, epoch);
    let mut barrier = None;
    let branch = if live_entry {
        // Does NOT call request_local_command_stop_recovery: TaskRun stays Running.
        store
            .mark_local_command_recovery_unconfirmed(&candidate, &candidate.identity.node_id, epoch)
            .unwrap();
        barrier = Some(checkpoint::before_settle(
            context,
            saved,
            cut,
            &store,
            &trust,
            LocalCommandAttemptState::StopUnconfirmed,
            "stop_unconfirmed",
        ));
        if held.area().is_populated().unwrap() {
            orphan::observe(context, saved, &held, &cut.live.association);
            context.deadline.check();
            held.area().terminate(Duration::from_millis(20)).unwrap();
            context.deadline.check();
            Branch::LiveOrphanStop
        } else {
            Branch::LiveAtEntryEmptyBeforeStop
        }
    } else {
        Branch::RunningAtCrashAlreadyEmpty
    };
    // Unreadable/missing/replaced never becomes empty. Fresh move-only proof only.
    let empty = held.area().prove_empty().unwrap();
    empty.revalidate().unwrap();
    context.deadline.check();
    store
        .settle_local_command_outcome_unknown_recovery(
            &candidate,
            &candidate.identity.node_id,
            epoch,
            empty,
        )
        .unwrap();
    let settled = super::observations::stream(&store, saved, TaskRunState::Unrecoverable);
    assert_eq!(settled.0, cut.durable.stream_version + 2);
    assert_eq!(settled.1.len(), cut.durable.event_ids.len() + 2);
    assert_eq!(
        &settled.1[..cut.durable.event_ids.len()],
        cut.durable.event_ids.as_slice()
    );
    let events = store.load_task_run(candidate.identity.taskrun_id).unwrap();
    assert!(matches!(
        events.events[cut.durable.event_ids.len()].payload(),
        TaskRunEvent::ReconciliationStarted
    ));
    assert!(matches!(
        events.events[cut.durable.event_ids.len() + 1].payload(),
        TaskRunEvent::Unrecoverable
    ));
    let original = checkpoint::settled(context, saved, cut, &store, &trust, epoch, &settled);
    retained(&store, &candidate);
    // Original immutable Running candidate reused, fresh proof, no original owner.
    let empty = held.area().prove_empty().unwrap();
    empty.revalidate().unwrap();
    store
        .settle_local_command_outcome_unknown_recovery(
            &candidate,
            &candidate.identity.node_id,
            epoch,
            empty,
        )
        .unwrap();
    assert_eq!(
        checkpoint::settled(context, saved, cut, &store, &trust, epoch, &settled),
        original
    );
    retained(&store, &candidate);
    drop(store);
    drop(trust);
    let (store, trust, next_epoch) = bootstrap::open(context, saved);
    assert!(next_epoch > epoch);
    authorize(&store, &candidate, next_epoch);
    assert_eq!(
        checkpoint::settled(context, saved, cut, &store, &trust, epoch, &settled),
        original
    );
    let empty = held.area().prove_empty().unwrap();
    empty.revalidate().unwrap();
    store
        .settle_local_command_outcome_unknown_recovery(
            &candidate,
            &candidate.identity.node_id,
            next_epoch,
            empty,
        )
        .unwrap();
    assert_eq!(
        checkpoint::settled(context, saved, cut, &store, &trust, epoch, &settled),
        original
    );
    retained(&store, &candidate);
    assert_eq!(candidate.state, LocalCommandAttemptState::Running);
    assert_eq!(candidate.exit_code, None);
    held.area().prove_empty().unwrap().revalidate().unwrap();
    held.into_area(context).remove_empty().unwrap();
    assert!(managed.area_is_absent(&saved.area_identity()).unwrap());
    let result = ResultRecord {
        original_digest: chain.original_digest.clone(),
        cut_digest: chain.cut_digest.clone(),
        ack_digest: ack_digest.clone(),
        after_ack_digest: after_digest.clone(),
        recovery_pid: std::process::id(),
        epoch,
        next_epoch,
        branch,
        barrier,
        settled_attempt: original.attempt,
        receipts: original.receipts,
        version: settled.0,
        events: settled.1,
        replay_same_epoch: true,
        replay_newer_epoch: true,
        removed: true,
    };
    result.validate(
        context,
        saved,
        cut,
        &chain.original_digest,
        &chain.cut_digest,
        &ack_digest,
        &after_digest,
    );
    require(record_publication::publish(
        context,
        Name::RecoveryResult,
        &result,
    ));
    context.deadline.check();
}
