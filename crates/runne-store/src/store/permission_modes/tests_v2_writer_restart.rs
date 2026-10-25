//! Actual process exit/reopen of logical RiskBased ceremonies only.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "tests_v2_writer_restart_history.rs"]
mod history;
#[path = "tests_v2_writer_restart_metadata.rs"]
mod metadata;
#[path = "tests_v2_writer_restart_recovery.rs"]
mod recovery;

const ROLE: &str = "RUNNE_R05_WRITER_RESTART_ROLE";
const ROOT: &str = "RUNNE_R05_WRITER_RESTART_ROOT";
const TARGET: &str = "store::permission_modes::tests_v2::writer_restart::actual_writer_exit_reopens_logical_risk_based_ceremonies";

#[test]
fn actual_writer_exit_reopens_logical_risk_based_ceremonies() {
    match std::env::var_os(ROLE) {
        None => {
            assert!(std::env::var_os(ROOT).is_none(), "root without role");
            for case in ["pending", "committed"] {
                supervise(case);
            }
        }
        Some(role) => {
            let role = role.to_str().expect("UTF-8 role");
            let (writer, case) = match role {
                "writer-pending" => (true, "pending"),
                "writer-committed" => (true, "committed"),
                "recover-pending" => (false, "pending"),
                "recover-committed" => (false, "committed"),
                _ => panic!("unknown restart role"),
            };
            let root = child_root();
            if writer {
                history::write_and_exit(&root, case);
            } else {
                recovery::recover(&root, case);
            }
        }
    }
}

fn child_root() -> PathBuf {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = PathBuf::from(std::env::var_os(ROOT).expect("child root"));
    assert!(root.is_absolute());
    assert_eq!(std::fs::canonicalize(&root).unwrap(), root);
    let info = std::fs::symlink_metadata(&root).unwrap();
    assert!(info.is_dir() && !info.file_type().is_symlink());
    assert_eq!(info.permissions().mode() & 0o777, 0o700);
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .unwrap();
    let ids: Vec<u32> = uid
        .split_whitespace()
        .map(|id| id.parse().unwrap())
        .collect();
    assert_eq!(ids.len(), 4);
    assert_eq!(info.uid(), ids[1]);
    assert_eq!(PathBuf::from(std::env::var_os("TMPDIR").unwrap()), root);
    root
}

fn supervise(case: &str) {
    use std::os::unix::fs::PermissionsExt;
    let outer = tempfile::tempdir().unwrap();
    std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = std::fs::canonicalize(outer.path()).unwrap();
    // Two histories total <=40s; each shares one 20s deadline for both children.
    let deadline = Instant::now() + Duration::from_secs(20);
    let writer_pid = run_child(&root, &format!("writer-{case}"), deadline, true);
    let checkpoint = metadata::read(&root, "checkpoint.json", case);
    assert!(checkpoint.recovered_pid.is_none());
    assert_eq!(checkpoint.writer_pid, writer_pid);
    let recovery_pid = run_child(&root, &format!("recover-{case}"), deadline, false);
    let result = metadata::read(&root, "result.json", case);
    assert_eq!(result.recovered_pid, Some(recovery_pid));
    let mut expected = checkpoint;
    expected.recovered_pid = result.recovered_pid;
    assert_eq!(result, expected);
    assert!(Instant::now() < deadline, "history deadline exceeded");
    println!("\nR05_WRITER_RESTART case={case} writer_signal=6 recovery_exit=0");
}

struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_child(root: &Path, role: &str, deadline: Instant, crashed_writer: bool) -> u32 {
    use std::os::unix::process::ExitStatusExt;
    assert!(Instant::now() < deadline);
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TARGET, "--nocapture", "--test-threads=1"])
        .env_remove(ROLE)
        .env_remove(ROOT)
        .env(ROLE, role)
        .env(ROOT, root)
        .env("TMPDIR", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut owned = OwnedChild(Some(child));
    loop {
        if let Some(status) = owned.0.as_mut().unwrap().try_wait().unwrap() {
            owned.0.take();
            if crashed_writer {
                assert_eq!(
                    status.signal(),
                    Some(libc::SIGABRT),
                    "unexpected {role} signal"
                );
                assert_eq!(status.code(), None);
            } else {
                assert_eq!(status.code(), Some(0), "unexpected {role} exit");
                assert_eq!(status.signal(), None);
            }
            return pid;
        }
        assert!(Instant::now() < deadline, "{role} deadline exceeded");
        std::thread::sleep(Duration::from_millis(10));
    }
}
