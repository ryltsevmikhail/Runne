use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::{require_current_executable_file, require_no_extended_acl};

const EXECUTABLE_CHILD: &str = "tests::current_executable_replacement_child";
const EXECUTABLE_PATH: &str = "RUNNE_FILE_SECURITY_EXECUTABLE_PATH";
const READY_PATH: &str = "RUNNE_FILE_SECURITY_READY_PATH";
const CONTINUE_PATH: &str = "RUNNE_FILE_SECURITY_CONTINUE_PATH";

fn chmod(arguments: &[&str], path: &Path) {
    assert!(
        Command::new("/bin/chmod")
            .args(arguments)
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn rejects_acl_despite_readonly_mode_and_rechecks_the_same_descriptor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy");
    let file = File::create(&path).unwrap();
    chmod(&["-N"], &path);
    chmod(&["0444"], &path);
    require_no_extended_acl(file.as_fd()).unwrap();
    chmod(&["+a", "everyone allow write,append"], &path);
    assert!(require_no_extended_acl(file.as_fd()).is_err());
    chmod(&["-N"], &path);
    require_no_extended_acl(file.as_fd()).unwrap();
}

#[test]
fn rejects_directory_acl_without_resolving_principals_or_allow_rules() {
    let directory = tempfile::tempdir().unwrap();
    let file = File::open(directory.path()).unwrap();
    chmod(&["-N"], directory.path());
    require_no_extended_acl(file.as_fd()).unwrap();
    chmod(&["+a", "everyone deny delete"], directory.path());
    assert!(require_no_extended_acl(file.as_fd()).is_err());
    chmod(&["-N"], directory.path());
}

#[test]
fn native_query_error_is_never_admitted() {
    // SAFETY: the native shim accepts an integer and handles OS errors. No invalid
    // BorrowedFd is constructed, and this call cannot close any descriptor.
    assert_eq!(unsafe { super::runne_macos_fd_has_no_extended_acl(-1) }, 0);
}

#[test]
fn current_executable_is_accepted_and_unrelated_files_are_rejected() {
    let executable = File::open(std::env::current_exe().unwrap()).unwrap();
    require_current_executable_file(executable.as_fd()).unwrap();
    let unrelated = tempfile::NamedTempFile::new().unwrap();
    assert!(require_current_executable_file(unrelated.as_file().as_fd()).is_err());
    let dylib = File::open("/usr/lib/libobjc-trampolines.dylib").unwrap();
    assert!(require_current_executable_file(dylib.as_fd()).is_err());
}

#[test]
fn replaced_executable_child_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let original = std::env::current_exe().unwrap();
    let executable = directory.path().join("runner-a");
    let replacement = directory.path().join("runner-b");
    fs::copy(&original, &executable).unwrap();
    fs::copy(&original, &replacement).unwrap();
    for path in [&executable, &replacement] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ready = directory.path().join("ready");
    let continue_path = directory.path().join("continue");
    let mut child = Command::new(&executable)
        .args(["--exact", EXECUTABLE_CHILD])
        .env(EXECUTABLE_PATH, &executable)
        .env(READY_PATH, &ready)
        .env(CONTINUE_PATH, &continue_path)
        .spawn()
        .unwrap();
    wait_for(&ready);
    fs::rename(&replacement, &executable).unwrap();
    fs::write(&continue_path, []).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn current_executable_replacement_child() {
    let Some(executable) = std::env::var_os(EXECUTABLE_PATH) else {
        return;
    };
    let retained = File::open(&executable).unwrap();
    fs::write(std::env::var_os(READY_PATH).unwrap(), []).unwrap();
    wait_for(Path::new(&std::env::var_os(CONTINUE_PATH).unwrap()));
    let replacement = File::open(&executable).unwrap();
    assert!(require_current_executable_file(replacement.as_fd()).is_err());
    assert!(require_current_executable_file(retained.as_fd()).is_err());
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
