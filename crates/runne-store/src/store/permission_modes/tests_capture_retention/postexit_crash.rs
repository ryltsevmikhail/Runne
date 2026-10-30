//! Guest-only natural exit -> abort -> conservative public recovery history.
use super::{ceremony, fixture, target};
#[path = "../tests_admitted_retention/approval.rs"]
mod approval;
#[path = "postexit_invocation_control_reopen.rs"]
mod control_reopen;
#[path = "postexit_invocation_control.rs"]
mod invocation_control;
#[path = "postexit_invocation_owner.rs"]
mod invocation_owner;
#[path = "postexit_invocation_refusal.rs"]
mod invocation_refusal;
#[path = "postexit_invocation_request.rs"]
mod invocation_request;
#[path = "postexit_invocation_rows.rs"]
mod invocation_rows;
#[path = "postexit_metadata.rs"]
mod metadata;
#[path = "postexit_observations.rs"]
mod observations;
#[path = "postexit_paths.rs"]
mod paths;
#[path = "postexit_receipts.rs"]
mod receipts;
#[path = "postexit_recovery.rs"]
mod recovery;
#[path = "postexit_restart_refusal.rs"]
mod restart_refusal;
#[path = "postexit_writer.rs"]
mod writer;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ROLE: &str = "RUNNE_R05_POSTEXIT_ROLE";
const ROOT: &str = "RUNNE_R05_POSTEXIT_ROOT";
const RUN: &str = "RUNNE_R05_POSTEXIT_RUN";
const CGROUP: &str = "RUNNE_R05_POSTEXIT_CGROUP";
const MOUNT: &str = "RUNNE_R05_POSTEXIT_MOUNT";
const TARGET: &str = "store::permission_modes::tests_capture_retention::postexit_crash::natural_exit_abort_recovers_original_area_as_unknown";

#[test]
fn natural_exit_abort_recovers_original_area_as_unknown() {
    history(TARGET, History::Original);
}

#[test]
fn natural_exit_abort_unknown_refuses_fresh_attempt_start() {
    history(
        "store::permission_modes::tests_capture_retention::postexit_crash::natural_exit_abort_unknown_refuses_fresh_attempt_start",
        History::FreshAttempt,
    );
}

#[test]
fn natural_exit_abort_unknown_refuses_fresh_invocation_capture() {
    history(
        "store::permission_modes::tests_capture_retention::postexit_crash::natural_exit_abort_unknown_refuses_fresh_invocation_capture",
        History::FreshInvocation,
    );
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum History {
    Original,
    FreshAttempt,
    FreshInvocation,
}

fn history(selected: &str, history: History) {
    let role = std::env::var_os(ROLE).map(|value| value.into_string().expect("UTF-8 closed role"));
    match role.as_deref() {
        None => {
            for name in [ROOT, RUN, CGROUP, MOUNT] {
                assert!(std::env::var_os(name).is_none(), "context without role");
            }
            supervise(selected, history);
        }
        Some(role @ ("writer" | "recovery")) => {
            let root = PathBuf::from(std::env::var_os(ROOT).expect("child root"));
            paths::private_root(&root);
            let context = metadata::Context::inherited();
            context.assert_controller();
            if role == "writer" {
                if history == History::FreshInvocation {
                    writer::write_and_abort_with_request(&root, context);
                } else {
                    writer::write_and_abort(&root, context);
                }
            } else {
                match history {
                    History::Original => recovery::recover(&root, &context),
                    History::FreshAttempt => {
                        recovery::recover_with_restart_refusal(&root, &context)
                    }
                    History::FreshInvocation => {
                        recovery::recover_with_invocation_refusal(&root, &context)
                    }
                }
            }
        }
        Some(_) => panic!("unknown postexit role"),
    }
}

fn supervise(selected: &str, history: History) {
    use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
    let outer = tempfile::tempdir().unwrap();
    std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // Retain on failure: no filesystem cleanup may imply that a cgroup is empty.
    // Isolated guest init must STOP/poweroff on any failed libtest result.
    let root = outer.keep();
    paths::private_root(&root);
    let context = metadata::Context::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let (writer_pid, status) = run_child(&root, "writer", &context, deadline, selected);
    assert_eq!(
        status.signal(),
        Some(6),
        "writer must abort after valid cut"
    );
    assert_eq!(status.code(), None);
    let area: metadata::Area = paths::read(&root, "area.json");
    area.validate(&root, &context);
    assert_eq!(area.writer_pid, writer_pid);
    let cut: metadata::Cut = paths::read(&root, "cut.json");
    cut.validate(&area);
    let request = (history == History::FreshInvocation).then(|| {
        let value: invocation_request::RequestRecord = paths::read(&root, "request.json");
        assert_eq!(value.area, area);
        value
    });
    let (recovery_pid, status) = run_child(&root, "recovery", &context, deadline, selected);
    assert_eq!(status.code(), Some(0), "recovery failed");
    assert_eq!(status.signal(), None);
    assert_ne!(writer_pid, recovery_pid);
    let result: metadata::ResultRecord = paths::read(&root, "result.json");
    assert_eq!(result.version, 1);
    assert_eq!(result.role, "recovery");
    assert_eq!(result.cut, cut);
    assert_eq!(result.recovery_pid, recovery_pid);
    assert!(result.removed);
    assert_eq!(paths::read::<metadata::Area>(&root, "area.json"), area);
    assert_eq!(paths::read::<metadata::Cut>(&root, "cut.json"), cut);
    if let Some(request) = request {
        assert_eq!(
            paths::read::<invocation_request::RequestRecord>(&root, "request.json"),
            request
        );
    }
    context.assert_controller();
    let managed =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    assert!(managed.area_is_absent(&area.area_identity()).unwrap());
    assert_eq!(std::fs::read(area.marker(&root)).unwrap(), b"once");
    assert!(
        Instant::now() < deadline,
        "shared history deadline exceeded"
    );
    std::fs::remove_dir_all(&root).unwrap();
    if history == History::FreshInvocation {
        println!(
            "\nR05_INVOCATION_REFUSAL writer_signal=6 recovery_exit=0 fresh_invocation_refused=1 control_settled=1"
        );
    } else if history == History::FreshAttempt {
        println!("\nR05_RESTART_REFUSAL writer_signal=6 recovery_exit=0 fresh_attempt_refused=1");
    } else {
        println!("\nR05_NATIVE_POSTEXIT writer_signal=6 recovery_exit=0");
    }
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
    deadline: Instant,
    selected: &str,
) -> (u32, ExitStatus) {
    assert!(Instant::now() < deadline);
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", selected, "--nocapture", "--test-threads=1"])
        .env(ROLE, role)
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
            assert!(Instant::now() < deadline, "child completed too late");
            return (pid, status);
        }
        assert!(Instant::now() < deadline, "{role} deadline exceeded");
        std::thread::sleep(Duration::from_millis(5));
    }
}
