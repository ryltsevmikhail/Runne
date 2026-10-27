//! Guest-only released cancellation -> owned stop/reap -> abort -> retained recovery.
use super::{ceremony, fixture, target};
#[path = "../tests_admitted_retention/approval.rs"]
mod approval;
#[path = "cancellation_attempt.rs"]
mod attempt;
#[path = "cancellation_bootstrap.rs"]
mod bootstrap;
#[path = "cancellation_clock.rs"]
mod budget;
#[path = "cancellation_metadata.rs"]
mod metadata;
#[path = "cancellation_native.rs"]
mod native;
#[path = "postexit_observations.rs"]
mod observations;
#[path = "postexit_paths.rs"]
mod paths;
#[path = "cancellation_receipts.rs"]
mod receipts;
#[path = "cancellation_records.rs"]
mod records;
#[path = "cancellation_recovery.rs"]
mod recovery;
#[path = "cancellation_writer.rs"]
mod writer;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

const CONTROLLER: &str = "RUNNE_G3_CANCEL_CONTROLLER_PID";
const ROLE: &str = "RUNNE_G3_CANCEL_ROLE";
const ROOT: &str = "RUNNE_G3_CANCEL_ROOT";
const RUN: &str = "RUNNE_G3_CANCEL_RUN";
const CGROUP: &str = "RUNNE_G3_CANCEL_CGROUP";
const MOUNT: &str = "RUNNE_G3_CANCEL_MOUNT";
const TARGET: &str = "store::permission_modes::tests_capture_retention::cancellation_crash::released_cancel_stop_abort_recovers_cancellation_once";

#[test]
fn released_cancel_stop_abort_recovers_cancellation_once() {
    let role = std::env::var_os(ROLE).map(|value| value.into_string().expect("UTF-8 closed role"));
    match role.as_deref() {
        None => {
            for name in [ROOT, RUN, CGROUP, MOUNT, budget::ENV, CONTROLLER] {
                assert!(std::env::var_os(name).is_none(), "context without role");
            }
            supervise();
        }
        Some(role @ ("writer" | "recovery")) => {
            let root = PathBuf::from(std::env::var_os(ROOT).expect("child root"));
            paths::private_root(&root);
            let context = metadata::Context::inherited();
            context.assert_controller();
            context.assert_parent();
            assert_ne!(std::process::id(), context.controller_pid);
            if role == "writer" {
                writer::write_and_abort(&root, context, budget::Deadline::inherited());
            } else {
                recovery::recover(&root, &context, budget::Deadline::inherited());
            }
        }
        Some(_) => panic!("unknown cancellation role"),
    }
}

fn supervise() {
    use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
    let outer = tempfile::tempdir().unwrap();
    std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // Retain on failure: no filesystem cleanup may imply that a cgroup is empty.
    // Isolated guest init must STOP/poweroff on any failed libtest result.
    let root = outer.keep();
    paths::private_root(&root);
    let context = metadata::Context::new();
    let deadline = budget::Deadline(context.deadline_ns);
    let (writer_pid, status) = run_child(&root, "writer", &context, deadline);
    assert_eq!(
        status.signal(),
        Some(6),
        "writer must abort after valid cut"
    );
    assert_eq!(status.code(), None);
    let area: metadata::Area = paths::read(&root, "area.json");
    area.validate(&root, &context);
    assert_eq!(area.writer_pid, writer_pid);
    let cut: records::Cut = paths::read(&root, "cut.json");
    cut.validate(&area);
    records::absent(&root, &area);
    let (recovery_pid, status) = run_child(&root, "recovery", &context, deadline);
    assert_eq!(status.code(), Some(0), "recovery failed");
    assert_eq!(status.signal(), None);
    assert_ne!(writer_pid, recovery_pid);
    let result: records::ResultRecord = paths::read(&root, "result.json");
    assert_eq!(result.version, 1);
    assert_eq!(result.role, "recovery");
    assert_eq!(result.cut, cut);
    assert_eq!(result.recovery_pid, recovery_pid);
    assert!(result.removed);
    assert_eq!(paths::read::<metadata::Area>(&root, "area.json"), area);
    assert_eq!(paths::read::<records::Cut>(&root, "cut.json"), cut);
    context.assert_controller();
    let managed =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    assert!(managed.area_is_absent(&area.area_identity()).unwrap());
    records::absent(&root, &area);
    assert!(deadline.live(), "shared history deadline exceeded");
    std::fs::remove_dir_all(&root).unwrap();
    println!("\nG3_RELEASED_CANCEL_STOP_ABORT writer_signal=6 recovery_exit=0");
}

struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            // Only this directly owned child. Collection failure remains failure;
            // no original-area removal is attempted on any failure path.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_child(
    root: &Path,
    role: &str,
    context: &metadata::Context,
    deadline: budget::Deadline,
) -> (u32, ExitStatus) {
    assert!(deadline.live());
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TARGET, "--nocapture", "--test-threads=1"])
        .env(ROLE, role)
        .env(CONTROLLER, context.controller_pid.to_string())
        .env(budget::ENV, deadline.0.to_string())
        .env(ROOT, root)
        .env(RUN, &context.run)
        .env(CGROUP, &context.cgroup)
        .env(MOUNT, &context.mount)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let pid = child.id();
    assert_ne!(pid, std::process::id());
    let mut owned = OwnedChild(Some(child));
    loop {
        if let Some(status) = owned.0.as_mut().unwrap().try_wait().unwrap() {
            owned.0.take();
            assert!(deadline.live(), "child completed too late");
            return (pid, status);
        }
        assert!(deadline.live(), "{role} deadline exceeded");
        std::thread::sleep(Duration::from_millis(5));
    }
}
