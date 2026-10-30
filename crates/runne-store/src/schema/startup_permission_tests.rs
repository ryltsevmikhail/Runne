//! Fresh owned DB/canaries only. Execute in a reviewed bounded Linux packet.
use super::*;
use std::io::Write;
use std::{fs, os::unix::fs::{PermissionsExt, symlink}, path::Path, process::{Child, Command, Stdio}, time::{Duration, Instant}};

fn database() -> (tempfile::TempDir, ManagedConnection) {
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    let daemon = runtime.join("daemon");
    fs::create_dir_all(&daemon).unwrap();
    for path in [root.path(), runtime.as_path(), daemon.as_path()] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let writer = open_managed_connection(&daemon.join("store.sqlite"), ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    (root, writer)
}
fn mode(path: &Path) -> u32 { fs::metadata(path).unwrap().permissions().mode() & 0o7777 }
fn canary(path: &Path, permissions: u32) {
    fs::write(path, b"startup-permission-canary").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(permissions)).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"startup-permission-canary");
    assert_eq!(mode(path), permissions);
}

#[test]
fn startup_inspection_does_not_chmod_a_caller_selected_path() {
    let (root, writer) = database();
    let unrelated = root.path().join("unrelated");
    canary(&unrelated, 0o640);
    // This API remains compatible; even a nonempty legacy argument is inert.
    run_startup_gates_raw(&writer, unrelated.to_str().unwrap()).unwrap();
    assert_eq!(mode(&unrelated), 0o640);
    assert_eq!(fs::read(&unrelated).unwrap(), b"startup-permission-canary");
    assert_eq!(mode(&root.path().join("runtime/daemon/store.sqlite")), 0o600);
    drop(writer);
    root.close().unwrap();
}

struct Collected(Option<Child>);
impl Drop for Collected {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn collect(mut child: Collected, deadline: Instant) {
    loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            child.0 = None; // try_wait has collected the direct child.
            assert!(Instant::now() < deadline, "startup permission child observed too late");
            assert!(status.success(), "startup permission child: {status}");
            return;
        }
        assert!(Instant::now() < deadline, "bounded startup permission child");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn managed_startup_does_not_chmod_cwd_sidecars() {
    const ROLE: &str = "RUNNE_TEST_STARTUP_PERMISSION_ROLE";
    if let Ok(role) = std::env::var(ROLE) {
        assert!(matches!(role.as_str(), "regular" | "symlink"));
        let cwd = std::env::current_dir().unwrap();
        let wal = cwd.join("-wal");
        let shm = cwd.join("-shm");
        assert_eq!(mode(&wal), 0o640);
        assert_eq!(mode(&shm), 0o644);
        assert_eq!(fs::read(&wal).unwrap(), b"startup-permission-canary");
        assert_eq!(fs::read(&shm).unwrap(), b"startup-permission-canary");
        if role == "symlink" { assert!(fs::symlink_metadata(&wal).unwrap().file_type().is_symlink()); }
        let (root, writer) = database();
        readiness_from_managed(&writer).unwrap();
        publication_from_managed(&writer).unwrap();
        assert_eq!(mode(&wal), 0o640);
        assert_eq!(mode(&shm), 0o644);
        assert_eq!(fs::read(&wal).unwrap(), b"startup-permission-canary");
        assert_eq!(fs::read(&shm).unwrap(), b"startup-permission-canary");
        assert_eq!(mode(&root.path().join("runtime/daemon/store.sqlite")), 0o600);
        drop(writer);
        root.close().unwrap();
        let mut receipt = fs::OpenOptions::new().create_new(true).write(true)
            .open(cwd.join("verified-role")).unwrap();
        receipt.write_all(role.as_bytes()).unwrap();
        receipt.sync_all().unwrap();
        return;
    }
    // CWD is process-global: only isolated child processes ever change it.
    let deadline = Instant::now() + Duration::from_secs(10);
    let full = concat!(module_path!(), "::managed_startup_does_not_chmod_cwd_sidecars");
    let exact = full.split_once("::").unwrap().1;
    for role in ["regular", "symlink"] {
        let root = tempfile::tempdir().unwrap();
        canary(&root.path().join("-shm"), 0o644);
        if role == "regular" { canary(&root.path().join("-wal"), 0o640); }
        else {
            let target = root.path().join("owned-target");
            canary(&target, 0o640);
            symlink(&target, root.path().join("-wal")).unwrap();
        }
        assert!(Instant::now() < deadline, "startup permission spawn budget");
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", exact, "--nocapture", "--test-threads=1"])
            .env(ROLE, role).current_dir(root.path()).stdin(Stdio::null())
            .spawn().unwrap();
        collect(Collected(Some(child)), deadline);
        assert_eq!(fs::read(root.path().join("verified-role")).unwrap(), role.as_bytes());
        assert_eq!(mode(&root.path().join("-wal")), 0o640);
        assert_eq!(mode(&root.path().join("-shm")), 0o644);
        root.close().unwrap();
    }
    assert!(Instant::now() < deadline, "startup permission completion budget");
}
