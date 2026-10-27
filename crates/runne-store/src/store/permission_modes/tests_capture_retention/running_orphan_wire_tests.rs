//! Pure synthetic source vectors; NOTRUN, no process/filesystem actions.
use super::wire::{Branch, Record};
use runne_platform::process_managed_area::ManagedAreaIdentity;

fn record(branch: Branch) -> Record {
    let mut area = [0x11; 100];
    area[..4].copy_from_slice(b"RMA1");
    Record {
        source: [0xaa; 32],
        artifact: [0xbb; 32],
        run: [0xcc; 16],
        supervisor: 2,
        writer: 3,
        recovery: 4,
        native: i32::MAX as u32,
        native_start: u64::MAX,
        area: ManagedAreaIdentity::from_bytes(&area).unwrap(),
        branch,
    }
}

#[test]
fn canonical_closed_branches_and_full_identity() {
    for (branch, label) in [
        (
            Branch::RunningAtCrashAlreadyEmpty,
            "RUNNING_AT_CRASH_ALREADY_EMPTY",
        ),
        (
            Branch::LiveAtEntryEmptyBeforeStop,
            "LIVE_AT_ENTRY_EMPTY_BEFORE_STOP",
        ),
        (Branch::LiveOrphanStop, "LIVE_ORPHAN_STOP"),
    ] {
        let line = record(branch).line().unwrap();
        assert!(line.starts_with("RUNNE_R05_COLLECTOR_PROVISIONAL_V1 source="));
        let fields: Vec<_> = line.trim_end_matches('\n').split(' ').collect();
        assert_eq!(fields.len(), 11);
        assert_eq!(fields[1], format!("source={}", "aa".repeat(32)));
        assert_eq!(fields[2], format!("artifact={}", "bb".repeat(32)));
        assert_eq!(fields[3], format!("run={}", "cc".repeat(16)));
        assert_eq!(
            &fields[4..9],
            [
                "supervisor=2",
                "writer=3",
                "recovery=4",
                "native=2147483647",
                "native_start=18446744073709551615"
            ]
        );
        assert_eq!(fields[9], format!("area=524d4131{}", "11".repeat(96)));
        assert_eq!(fields[10], format!("branch={label}"));
        assert_eq!(line.bytes().filter(|value| *value == b'\n').count(), 1);
        assert!(line.ends_with('\n'));
    }
}

#[test]
fn pid_sentinels_collisions_and_c_width_are_refused() {
    for index in 0..4 {
        for bad in [0, 1, i32::MAX as u32 + 1, u32::MAX] {
            let mut value = record(Branch::LiveOrphanStop);
            let fields = [
                &mut value.supervisor,
                &mut value.writer,
                &mut value.recovery,
                &mut value.native,
            ];
            *fields.into_iter().nth(index).unwrap() = bad;
            assert!(value.line().is_err());
        }
    }
    let mut value = record(Branch::LiveOrphanStop);
    value.native = value.writer;
    assert!(value.line().is_err());
    value.native = i32::MAX as u32;
    value.native_start = 0;
    assert!(value.line().is_err());
}
