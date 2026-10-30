//! W keeps real native/Store/trust/held-area owners alive through deliberate SIGABRT.
use super::{
    after_ack::AfterAck,
    approval,
    association::Spawner,
    ceremony,
    context::CaseContext,
    control_result::ResultRecord,
    held_area::HeldAreaReader,
    helper_failure::require,
    live::{self, OutputTracker},
    metadata::Kind,
    native::{self, OwnedNative},
    record_protocol::Name,
    record_publication,
    records::{Ack, AfterReady, BeforeGo, Cut},
    setup, snapshot, target, wait_record,
};
use runne_application::permission_modes::PermissionMode;
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding};

pub(super) fn run(context: &CaseContext) -> ! {
    context.check_child();
    let (control, control_digest): (ResultRecord, String) =
        require(record_publication::read(context, Name::ControlResult));
    control.validate(context);
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
        Kind::Original,
        &b,
        &captured,
        area.identity().to_bytes().to_vec(),
    );
    control.distinct(&saved, &control_digest);
    // Exact original area/assignment/authority/trust record BEFORE any native spawn.
    let original_digest = require(record_publication::publish(
        context,
        Name::OriginalArea,
        &saved,
    ));
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
    let roster = [
        context.record.collector,
        context.record.supervisor,
        std::process::id(),
    ];
    let held = HeldAreaReader::reopen(context, &managed, &saved.area_identity(), saved.binding());
    let association = held.live_association(context, &spawner, pid, &roster);
    assert!(!child.child.was_released());
    assert_eq!(child.child.try_wait().unwrap(), None);
    let before = BeforeGo {
        original_digest: original_digest.clone(),
        association,
    };
    before.validate(&saved, &original_digest);
    let before_digest = require(record_publication::publish(
        context,
        Name::BeforeGo,
        &before,
    ));
    // H was collected before this independent pre-GO association assertion.
    assert_eq!(
        held.live_association(context, &spawner, pid, &roster),
        before.association
    );
    native::bind(&child.child, &saved);
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
        &before.association,
    );
    let ready = AfterReady {
        before_go_digest: before_digest,
        live,
    };
    ready.validate(&before, &ready.before_go_digest);
    let ready_digest = require(record_publication::publish(
        context,
        Name::AfterReady,
        &ready,
    ));
    let live = live::sample(
        context,
        &held,
        &spawner,
        pid,
        &roster,
        &mut child.child,
        &mut output,
        &ready.live.association,
    );
    let durable = snapshot::observe(context, &saved, &f.store, &f.trust);
    let cut = Cut {
        after_ready_digest: ready_digest.clone(),
        control_digest: control_digest.clone(),
        live,
        durable,
    };
    cut.validate(context, &saved, &ready, &ready_digest, &control_digest);
    let cut_digest = require(record_publication::publish(context, Name::RunningCut, &cut));
    // WAIT ONLY after publishing cut. S must collect its read helper, observe N,
    // and publish/collect ACK helper before its marker makes this wait finish.
    wait_record::wait(context, Name::SupervisorAck);
    let (ack, ack_digest): (Ack, String) =
        require(record_publication::read(context, Name::SupervisorAck));
    ack.validate(context, &cut, &cut_digest);
    let live = live::sample(
        context,
        &held,
        &spawner,
        pid,
        &roster,
        &mut child.child,
        &mut output,
        &ack.association,
    );
    let durable = snapshot::observe(context, &saved, &f.store, &f.trust);
    let after = AfterAck {
        ack_digest: ack_digest.clone(),
        live,
        durable,
    };
    after.validate(context, &ack, &ack_digest, &cut);
    let _after_digest = require(record_publication::publish(context, Name::AfterAck, &after));
    // LAST H collected. Never spawn a helper to attest this final assertion.
    native::bind(&child.child, &saved);
    assert_eq!(
        snapshot::observe(context, &saved, &f.store, &f.trust),
        cut.durable
    );
    assert_eq!(
        live::sample(
            context,
            &held,
            &spawner,
            pid,
            &roster,
            &mut child.child,
            &mut output,
            &ack.association
        ),
        cut.live
    );
    context.deadline.check();
    // No stop/reap/drop/terminal/empty operation or Store mutation before abort.
    std::process::abort()
}
