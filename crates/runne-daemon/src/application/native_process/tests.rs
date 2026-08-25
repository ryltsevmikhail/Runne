#[cfg(target_os = "linux")]
use runne_security::broker::process::ProcessInvocationIdV1;
use std::fs;

fn verified_root(path: &std::path::Path) -> VerifiedRootHandle {
    let canonical = fs::canonicalize(path).expect("canonical root path");
    VerifiedRootHandle::open(&canonical).expect("verified root")
}

#[test]
fn preparation_binds_open_file_identities_and_rejects_replay() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::create_dir(root.path().join("bin")).expect("bin");
    fs::create_dir(root.path().join("workspace")).expect("workspace");
    fs::write(root.path().join("bin/tool"), b"native-tool").expect("tool");
    let launcher = NativeOwnerBoundProcessLauncher::new(
        verified_root(root.path()),
    );
    let request = launcher
        .prepare([7; 32], "bin/tool", "workspace")
        .expect("prepared request");
    assert_eq!(request.request_digest(), &[7; 32]);
    assert_ne!(request.executable().identity().content_digest(), &[0; 32]);
    assert_eq!(
        launcher.prepare([7; 32], "bin/tool", "workspace"),
        Err(NativeProcessPreparationError::Rejected)
    );
}

#[cfg(unix)]
#[test]
fn preparation_rejects_symlinked_executable() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::create_dir(root.path().join("workspace")).expect("workspace");
    std::os::unix::fs::symlink("/bin/sh", root.path().join("tool")).expect("symlink");
    let launcher = NativeOwnerBoundProcessLauncher::new(
        verified_root(root.path()),
    );
    assert_eq!(
        launcher.prepare([8; 32], "tool", "workspace"),
        Err(NativeProcessPreparationError::Rejected)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn re_adoption_rejects_a_pid_without_the_runtime_launch_nonce() {
    use runne_platform_ports::process::{
        HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1,
        ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessSessionIdV1,
    };
    let root = tempfile::tempdir().expect("temporary root");
    let launcher = NativeOwnerBoundProcessLauncher::new(
        verified_root(root.path()),
    );
    let binding = ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([1; 16]).unwrap(),
        ProcessAttemptIdV1::new([2; 16]).unwrap(),
        ProcessSessionIdV1::new([3; 16]).unwrap(),
        ProcessGenerationIdV1::new([4; 16]).unwrap(),
        HeldProcessTreeHandleV1::new([5; 16]).unwrap(),
    );
    let handle = OwnedProcessHandleV1::recovered(
        binding,
        ProcessInvocationIdV1::new([6; 16]).unwrap(),
        std::process::id(),
        [7; 32],
        [8; 16],
    )
    .unwrap();
    assert_eq!(
        launcher.re_adopt(handle),
        Err(OwnerBoundProcessError::OwnershipMismatch)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn re_adoption_accepts_the_exact_marker_and_stop_identity() {
    use runne_platform_ports::process::{
        HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1,
        ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessSessionIdV1,
    };
    use std::os::unix::process::CommandExt;
    let root = tempfile::tempdir().expect("temporary root");
    let launcher = NativeOwnerBoundProcessLauncher::new(
        verified_root(root.path()),
    );
    let nonce = [9; 16];
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .env(native_linux::LAUNCH_NONCE_ENV, hex::encode(nonce))
        .process_group(0)
        .spawn()
        .expect("test process");
    let pid = child.id();
    let start_identity = native_linux::start_identity(pid).expect("start identity");
    let binding = ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([1; 16]).unwrap(),
        ProcessAttemptIdV1::new([2; 16]).unwrap(),
        ProcessSessionIdV1::new([3; 16]).unwrap(),
        ProcessGenerationIdV1::new([4; 16]).unwrap(),
        HeldProcessTreeHandleV1::new([5; 16]).unwrap(),
    );
    let handle = OwnedProcessHandleV1::recovered(
        binding,
        ProcessInvocationIdV1::new([6; 16]).unwrap(),
        pid,
        start_identity,
        nonce,
    )
    .unwrap();
    assert!((0..50).any(|_| match launcher.re_adopt(handle.clone()) {
        Ok(()) => true,
        Err(_) => {
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        }
    }), "re-adopt exact process");
    launcher.stop(&handle).expect("stop adopted process");
    let _ = child.wait();
}
