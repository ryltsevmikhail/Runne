//! End-to-end tests for the signed helper and the rendered profile.

use std::fs::{self, File};
use std::io::{Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use super::MacOsSeatbeltProfileV1;

fn helper_binary_path() -> PathBuf {
    std::env::current_dir()
        .expect("current dir")
        .join("../../target/debug/runne-sandbox-helper")
}

fn build_helper() {
    let status = Command::new("cargo")
        .args(["build", "-p", "runne-sandbox-helper"])
        .status()
        .expect("spawn cargo build");
    assert!(status.success(), "cargo build runne-sandbox-helper failed");
}

fn seatbelt_available() -> bool {
    Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn signed_helper() -> (tempfile::TempDir, PathBuf) {
    build_helper();
    let directory = tempfile::tempdir().expect("temporary helper directory");
    let helper = directory.path().join("runne-sandbox-helper");
    fs::copy(helper_binary_path(), &helper).expect("copy helper");
    let status = Command::new("/usr/bin/codesign")
        .args(["--sign", "-", "--force", "--options", "runtime"])
        .arg(&helper)
        .status()
        .expect("spawn codesign");
    assert!(status.success(), "ad-hoc signing failed");
    let verified = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&helper)
        .status()
        .expect("spawn codesign --verify");
    assert!(verified.success(), "ad-hoc signature does not verify");
    (directory, helper)
}

fn dup_high(fd: RawFd) -> OwnedFd {
    // SAFETY: fd is valid for the duration of the call; the duplicate owns a
    // new descriptor and is closed by OwnedFd.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    assert!(duplicate >= 0, "cannot duplicate descriptor {fd}");
    // SAFETY: fcntl returned a new owned descriptor.
    unsafe { OwnedFd::from_raw_fd(duplicate) }
}

fn run_with_profile(
    helper: &Path,
    profile: &str,
    program: &str,
    arguments: &[&str],
    cwd: Option<&Path>,
) -> Output {
    let mut profile_file = tempfile::tempfile().expect("temporary profile");
    profile_file
        .write_all(profile.as_bytes())
        .expect("write profile");
    profile_file.rewind().expect("rewind profile");
    let profile_fd = dup_high(profile_file.as_raw_fd());
    let cwd_file = cwd.map(|path| File::open(path).expect("open working directory"));
    let cwd_fd = cwd_file.as_ref().map(|file| dup_high(file.as_raw_fd()));

    let mut command = Command::new(helper);
    command.arg("--profile-fd").arg("3");
    if cwd_fd.is_some() {
        command.arg("--cwd-fd").arg("4");
    }
    command.arg("--").arg(program).args(arguments);
    let profile_source = profile_fd.as_raw_fd();
    let cwd_source = cwd_fd.as_ref().map(AsRawFd::as_raw_fd);
    // SAFETY: dup2 only installs already-open descriptors into the fixed slots
    // the helper expects; no allocation or locking happens after fork.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(profile_source, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(source) = cwd_source {
                if libc::dup2(source, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command.output().expect("spawn signed helper")
}

#[test]
fn helper_applies_the_profile_before_exec() {
    if !seatbelt_available() {
        eprintln!("skipping: Seatbelt cannot be applied in this process tree");
        return;
    }
    let (_directory, helper) = signed_helper();
    let base = tempfile::tempdir().expect("temporary base");
    let workspace = base.path().join("workspace");
    let outside = base.path().join("outside");
    fs::create_dir(&workspace).expect("create workspace");
    fs::create_dir(&outside).expect("create outside directory");
    let workspace = fs::canonicalize(&workspace).expect("canonical workspace");
    let profile = MacOsSeatbeltProfileV1::new(&workspace)
        .expect("workspace profile")
        .render();

    let echo = run_with_profile(&helper, &profile, "/bin/echo", &["helper-ok"], None);
    assert!(echo.status.success(), "echo failed: {echo:?}");
    assert_eq!(echo.stdout, b"helper-ok\n");

    let denied = run_with_profile(&helper, &profile, "/bin/cat", &["/etc/passwd"], None);
    assert!(!denied.status.success(), "read /etc/passwd was allowed");

    let inside = workspace.join("inside.txt");
    let touched = run_with_profile(
        &helper,
        &profile,
        "/usr/bin/touch",
        &[inside.to_str().expect("utf-8 path")],
        None,
    );
    assert!(
        touched.status.success(),
        "workspace write failed: {touched:?}"
    );
    assert!(inside.is_file());

    let outside_file = outside.join("outside.txt");
    let blocked = run_with_profile(
        &helper,
        &profile,
        "/usr/bin/touch",
        &[outside_file.to_str().expect("utf-8 path")],
        None,
    );
    assert!(
        !blocked.status.success(),
        "write outside the workspace succeeded"
    );
    assert!(!outside_file.exists());
}

#[test]
fn helper_enters_the_supplied_working_directory() {
    if !seatbelt_available() {
        eprintln!("skipping: Seatbelt cannot be applied in this process tree");
        return;
    }
    let (_directory, helper) = signed_helper();
    let workspace = tempfile::tempdir().expect("temporary workspace");
    let canonical = fs::canonicalize(workspace.path()).expect("canonical workspace");
    let profile = MacOsSeatbeltProfileV1::new(&canonical)
        .expect("workspace profile")
        .render();

    let output = run_with_profile(&helper, &profile, "/bin/pwd", &[], Some(&canonical));
    assert!(output.status.success(), "pwd failed: {output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        canonical.to_str().expect("utf-8 workspace")
    );
}
