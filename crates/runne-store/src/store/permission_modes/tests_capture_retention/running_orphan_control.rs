//! Complete positive cancellation control finishes before W is launched.
use super::{
    approval,
    association::Spawner,
    attempt, cancel, ceremony,
    context::CaseContext,
    control_receipts,
    control_result::ResultRecord,
    fixture::Fixture,
    held_area::HeldAreaReader,
    helper_failure::require,
    live::{self, OutputTracker},
    metadata::Kind,
    native::{self, OwnedNative},
    observations,
    record_protocol::Name,
    record_publication, setup, snapshot, target, workspace,
};
use crate::store::LocalCommandAttemptState;
use runne_application::{permission_modes::PermissionMode, project_trust::ProjectTrustPersistence};
use runne_domain::task_run::TaskRunState;
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding};

pub(super) struct Completed {
    pub fixture: Fixture,
    pub result: ResultRecord,
    pub digest: String,
}

pub(super) fn run(context: &CaseContext) -> Completed {
    assert_eq!(std::process::id(), context.record.supervisor);
    let f = setup::fixture(context);
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let elf = std::fs::read("/bin/sh").unwrap();
    assert!(elf.starts_with(b"\x7fELF"));
    let (b, prepared) = target::prepare_with_executable(
        &f,
        vec!["tool".into(), "-c".into(), setup::WORKLOAD.into()],
        &elf,
    );
    let captured = f
        .store
        .capture_local_command_permission(&b, prepared.observation())
        .unwrap();
    let approval = approval::confirm_native_fixture(&f, &b);
    let receipt = f
        .store
        .admit_local_command_permission(&b, Some(approval))
        .unwrap();
    let id = b.assignment();
    let managed = LinuxManagedAreaRoot::open_current_cgroup().unwrap();
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
    let saved = setup::saved(
        context,
        &f,
        Kind::Control,
        &b,
        &captured,
        area.identity().to_bytes().to_vec(),
    );
    let spawner = Spawner::current(context.observer_deadline());
    assert!(spawner.children(context.observer_deadline()).is_empty());
    let mut child = OwnedNative::new(
        prepared
            .bind(b.clone())
            .unwrap()
            .spawn(&area, receipt, &[])
            .unwrap(),
        context.deadline,
    );
    native::bind(&child.child, &saved);
    let children = spawner.children(context.observer_deadline());
    assert_eq!(children.len(), 1);
    let pid = children[0];
    let roster = [context.record.collector, context.record.supervisor];
    let held = HeldAreaReader::reopen(context, &managed, &saved.area_identity(), saved.binding());
    let before_go = held.live_association(context, &spawner, pid, &roster);
    assert!(!child.child.was_released());
    assert_eq!(child.child.try_wait().unwrap(), None);
    f.store
        .release_local_command_permission(id, b.claim_stream_version(), &b, &area, &mut child.child)
        .unwrap();
    let mut output = OutputTracker::default();
    native::ready(context, &mut child, &mut output);
    let live = live::sample(
        context,
        &held,
        &spawner,
        pid,
        &roster,
        &mut child.child,
        &mut output,
        &before_go,
    );
    let before = snapshot::observe(context, &saved, &f.store, &f.trust);
    let requested = cancel::request(&f, &saved);
    assert_eq!(
        f.store
            .local_command_permission_stop_reason(id, &b)
            .unwrap(),
        Some(1)
    );
    let reader = observations::reader(context, &saved);
    let receipts = control_receipts::observe(
        &reader,
        &saved,
        requested.events.last().unwrap(),
        requested.version,
        None,
    );
    assert_eq!(attempt::observe(&reader, &saved, "running"), before.attempt);
    assert_eq!(observations::spent(&reader, &saved), before.spent);
    workspace::pending(context, &saved);
    // Proven durable public cancellation and exact receipts have been read back BEFORE physical stop.
    let exit = native::stop_control(
        context,
        &mut child,
        &held,
        &spawner,
        pid,
        &roster,
        &live.association,
    );
    workspace::pending(context, &saved);
    let fresh = observations::reader(context, &saved);
    assert_eq!(
        control_receipts::observe(
            &fresh,
            &saved,
            requested.events.last().unwrap(),
            requested.version,
            None
        ),
        receipts
    );
    assert_eq!(attempt::observe(&fresh, &saved, "running"), before.attempt);
    assert_eq!(observations::spent(&fresh, &saved), before.spent);
    observations::capture(&f.store, &saved, LocalCommandAttemptState::Running);
    assert_eq!(
        observations::stream(&f.store, &saved, TaskRunState::Cancelling),
        (requested.version, requested.events.clone())
    );
    assert_eq!(f.trust.load(f.trust_id()).unwrap(), saved.trust_record());
    drop(child); // disarmed only after actual owned collection and terminal evidence
    held.into_area(context).remove_empty().unwrap();
    assert!(managed.area_is_absent(&saved.area_identity()).unwrap());
    let result = ResultRecord {
        original: saved,
        live,
        before,
        requested,
        receipts,
        exit,
        reaped: true,
        eof: true,
        empty: true,
        removed: true,
    };
    result.validate(context);
    let digest = require(record_publication::publish(
        context,
        Name::ControlResult,
        &result,
    ));
    Completed {
        fixture: f,
        result,
        digest,
    }
}
