//! Controller oracle and actual role collection; guest init must collect descendants.
use super::*;
pub(super) fn supervise() {
    use runne_platform::process_managed_area::{
        LinuxManagedAreaRoot, ManagedAreaBinding, ManagedAreaIdentity,
    };
    use std::os::unix::process::ExitStatusExt;
    // This guard prevents accidental ordinary-host execution, not forged authority.
    // Acceptance also requires the independently admitted guest init/collector.
    assert_eq!(
        std::fs::read("/run/runne-d21-lostack-guest-v1").unwrap(),
        b"R05_OWNED_DISPOSABLE_GUEST_V1\n"
    );
    let root = tempfile::Builder::new()
        .prefix("lost-ack-success-")
        .tempdir_in("/dev/shm")
        .unwrap();
    let database = fixture::ControllerDatabase::create(&root).unwrap();
    let original = database.reference();
    let context = Context {
        path: original.path.into(),
        authority: original.authority,
        lineage: original.lineage,
        run: uuid::Uuid::now_v7().into_bytes(),
        controller: std::process::id(),
        cgroup: std::fs::read_to_string("/proc/self/cgroup").unwrap(),
        mount: std::fs::read_link("/proc/self/ns/mnt").unwrap(),
    };
    write(root.path(), "context.json", &context);
    let until = deadline();
    let mut owner = Owned::spawn(root.path(), "writer");
    let writer_pid = owner.0.as_ref().unwrap().id();
    while !root.path().join("intent-ready.json").exists() {
        pause(until);
    }
    let intent: Intent = read(root.path(), "intent-ready.json");
    assert_eq!(intent.writer, writer_pid);
    assert!(intent.workspace.starts_with(root.path()));
    Request::decode(&intent.request, &context.run).unwrap();
    intent.trust.check(root.path(), context.authority);
    let mut reader = context.reader();
    database.anchor().verify_reader(&reader).unwrap();
    let original_facts = facts::Facts::decode(&intent.original_facts).unwrap();
    original_facts.check_intent(&intent).unwrap();
    let observed = original_facts
        .observe(&context.path, database.anchor())
        .unwrap();
    // No commit allowed until C freezes the precommit request and original DB identity.
    write(root.path(), "commit-go.json", &context.run);
    loop {
        let count: i64 = reader
            .query_row(
                "SELECT count(*) FROM command_receipts WHERE command_id=?1",
                [intent.command.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(count <= 1);
        if count == 1 {
            break;
        }
        pause(until);
    }
    let (_, baseline) = original_facts.capture(observed).unwrap();
    assert_eq!(
        std::fs::read(intent.workspace.join("terminal-retry-marker")).unwrap(),
        format!("{}\n", uuid::Uuid::from_bytes(context.run)).as_bytes()
    );
    database.anchor().verify_reader(&reader).unwrap();
    write(root.path(), "abort-go.json", &context.run);
    assert_eq!(owner.wait(until).signal(), Some(6));
    intent.trust.check(root.path(), context.authority);
    // Exact committed rows survive actual owner death before any response.
    assert_eq!(logical_reader::capture(&mut reader).unwrap(), baseline);
    for role in ["recovery", "conflict", "recovery"] {
        let mut child = Owned::spawn(root.path(), role);
        let pid = child.0.as_ref().unwrap().id();
        assert_ne!(pid, writer_pid);
        assert_eq!(child.wait(until).code(), Some(0));
        intent.trust.check(root.path(), context.authority);
        database.anchor().verify_reader(&reader).unwrap();
        assert_eq!(logical_reader::capture(&mut reader).unwrap(), baseline);
        assert_eq!(
            std::fs::read(intent.workspace.join("terminal-retry-marker")).unwrap(),
            format!("{}\n", uuid::Uuid::from_bytes(context.run)).as_bytes()
        );
    }
    let managed = LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    let identity = ManagedAreaIdentity::from_bytes(&intent.area).unwrap();
    let binding = ManagedAreaBinding::new(
        intent.task,
        intent.attempt,
        intent.area[84..100].try_into().unwrap(),
    )
    .unwrap();
    let area = managed.reopen_area(identity, binding).unwrap();
    area.prove_empty().unwrap().revalidate().unwrap();
    let identity = area.identity().clone();
    area.remove_empty().unwrap();
    assert!(managed.area_is_absent(&identity).unwrap());
    drop(reader);
    drop(database);
    root.close().unwrap();
    println!(
        "R05_LOSTACK_SUBJECT owner_signal=6 receipt_recovery=3 key_conflict=1 no_redispatch=1 outer_collection_required=1"
    );
}
