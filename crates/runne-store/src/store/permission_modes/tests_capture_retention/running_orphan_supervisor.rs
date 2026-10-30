//! S owns W/R and enforces the complementary one-helper phase schedule.
use super::{
    chain,
    context::CaseContext,
    control,
    held_area::HeldAreaReader,
    helper_failure::require,
    observation_store,
    record_protocol::Name,
    record_publication,
    records::Ack,
    recovery_result::{Branch, ResultRecord},
    role::Role,
    role_child::RoleChild,
    snapshot, wait_record, wire,
};
use runne_platform::process_managed_area::LinuxManagedAreaRoot;
use std::os::unix::process::ExitStatusExt;

// Final checked C-collection publication is intentionally NOT implemented here.
// Returning this value is NOT test success and no selector may return Ok on it.
pub(super) struct CollectedCase {
    pub provisional: String,
    pub branch: Branch,
    pub writer_signal: i32,
    pub recovery_pid: u32,
}

pub(super) fn run(context: &CaseContext) -> CollectedCase {
    assert_eq!(std::process::id(), context.record.supervisor);
    let control = control::run(context); // actual stop/reap/empty/remove BEFORE W
    let mut writer = RoleChild::spawn(context, Role::Writer);
    let writer_pid = writer.id();
    assert!(![context.record.supervisor, context.record.collector].contains(&writer_pid));
    wait_record::wait(context, Name::RunningCut);
    writer.live();
    // W is WAIT ONLY. Every read H here is collected before native/ledger observation.
    let chain = chain::read(context);
    assert_eq!(chain.control, control.result);
    assert_eq!(chain.control_digest, control.digest);
    assert_eq!(chain.area.writer_pid, writer_pid);
    let managed = LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    let held = HeldAreaReader::reopen(
        context,
        &managed,
        &chain.area.area_identity(),
        chain.area.binding(),
    );
    let native = chain.cut.live.association.native;
    let roster = [
        context.record.collector,
        context.record.supervisor,
        writer_pid,
    ];
    let (store, trust) = observation_store::open(context, &chain.area);
    writer.live();
    let association =
        held.live_association(context, &chain.before.association.spawner, native, &roster);
    assert_eq!(association, chain.cut.live.association);
    let durable = snapshot::observe(context, &chain.area, &store, &trust);
    assert_eq!(durable, chain.cut.durable);
    assert_eq!(
        held.live_association(context, &chain.before.association.spawner, native, &roster),
        association
    );
    writer.live();
    let ack = Ack {
        cut_digest: chain.cut_digest.clone(),
        supervisor_pid: context.record.supervisor,
        association,
        durable,
    };
    ack.validate(context, &chain.cut, &chain.cut_digest);
    let ack_digest = require(record_publication::publish(
        context,
        Name::SupervisorAck,
        &ack,
    ));
    // ACK marker is LAST after actual H collection. WAIT W ONLY until collected.
    let status = writer.wait();
    assert_eq!(status.signal(), Some(6));
    assert_eq!(status.code(), None);
    drop(store);
    drop(trust);
    let (reread_ack, observed_ack_digest, _, after_digest) = chain::acknowledged(context, &chain);
    assert_eq!(reread_ack, ack);
    assert_eq!(observed_ack_digest, ack_digest);
    let mut recovery = RoleChild::spawn(context, Role::Recovery);
    let recovery_pid = recovery.id();
    assert!(
        ![
            writer_pid,
            native,
            context.record.supervisor,
            context.record.collector
        ]
        .contains(&recovery_pid)
    );
    let status = recovery.wait();
    assert_eq!(status.code(), Some(0));
    assert_eq!(status.signal(), None);
    let (result, _result_digest): (ResultRecord, String) =
        require(record_publication::read(context, Name::RecoveryResult));
    result.validate(
        context,
        &chain.area,
        &chain.cut,
        &chain.original_digest,
        &chain.cut_digest,
        &ack_digest,
        &after_digest,
    );
    assert_eq!(result.recovery_pid, recovery_pid);
    assert!(managed.area_is_absent(&chain.area.area_identity()).unwrap());
    assert!(
        managed
            .area_is_absent(&control.result.original.area_identity())
            .unwrap()
    );
    let branch = match result.branch {
        Branch::RunningAtCrashAlreadyEmpty => wire::Branch::RunningAtCrashAlreadyEmpty,
        Branch::LiveAtEntryEmptyBeforeStop => wire::Branch::LiveAtEntryEmptyBeforeStop,
        Branch::LiveOrphanStop => wire::Branch::LiveOrphanStop,
    };
    let record = wire::Record {
        source: hex::decode(&context.record.collection.source)
            .unwrap()
            .try_into()
            .unwrap(),
        artifact: hex::decode(&context.record.collection.artifact)
            .unwrap()
            .try_into()
            .unwrap(),
        run: hex::decode(&context.record.collection.nonce)
            .unwrap()
            .try_into()
            .unwrap(),
        supervisor: context.record.supervisor,
        writer: writer_pid,
        recovery: recovery_pid,
        native,
        native_start: chain.cut.live.association.start_ticks,
        area: chain.area.area_identity(),
        branch,
    };
    let provisional = record.line().unwrap();
    drop(held);
    drop(recovery);
    drop(writer); // actual role statuses already collected
    // Prevent TempDir drop racing explicit cleanup, without leaking open Store/native ownership.
    let control_area = control.result.original.clone();
    let super::fixture::Fixture {
        root,
        store,
        trust,
        native,
        held,
        project: _,
        scope: _,
        principal: _,
        launch: _,
    } = control.fixture;
    let control_path = root.path().to_path_buf();
    assert_eq!(root.keep(), control_path);
    drop(store);
    drop(trust);
    drop(native);
    drop(held);
    super::case_cleanup::remove(context, &chain.area, &control_area);
    CollectedCase {
        provisional,
        branch: result.branch,
        writer_signal: 6,
        recovery_pid,
    }
}
