use super::*;
use crate::local_command_macos::MacOsCommandError;
use std::time::Duration;

fn spec<'a>(
    executable: &'a Path,
    arguments: &'a [String],
    environment: &'a [(&'a str, &'a str)],
    timeout: Duration,
) -> MacOsCommandSpec<'a> {
    MacOsCommandSpec {
        executable,
        arguments,
        cwd: Path::new("/tmp"),
        environment,
        timeout,
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn captures_bounded_output_and_exit_code() {
    let arguments = args(&["-c", "printf hi; printf err >&2; exit 3"]);
    let mut child = MacOsManagedChild::spawn(&spec(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        Duration::from_secs(5),
    ))
    .unwrap();
    let exit = child.wait(Duration::from_secs(5)).unwrap();
    assert_eq!(exit.kind(), LinuxLeaderExitKindV1::Exited { code: 3 });
    assert_eq!(child.stdout(), b"hi");
    assert_eq!(child.stderr(), b"err");
    assert!(!child.stdout_truncated());
    child.area().prove_empty(Duration::from_secs(2)).unwrap();
}

#[test]
fn timeout_kills_the_group_and_reports_it() {
    let arguments = args(&["-c", "sleep 5"]);
    let mut child = MacOsManagedChild::spawn(&spec(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        Duration::from_millis(100),
    ))
    .unwrap();
    assert_eq!(
        child.wait(Duration::from_millis(100)).unwrap_err(),
        MacOsCommandError::Timeout
    );
    assert!(child.status().is_some());
    child.area().prove_empty(Duration::from_secs(2)).unwrap();
}

#[test]
fn group_termination_removes_background_descendants() {
    let arguments = args(&["-c", "sleep 30 & wait"]);
    let mut child = MacOsManagedChild::spawn(&spec(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        Duration::from_secs(5),
    ))
    .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    child.area().terminate();
    let _ = child.wait(Duration::from_secs(2));
    child.area().prove_empty(Duration::from_secs(3)).unwrap();
}

#[test]
fn output_is_truncated_at_the_bound() {
    let arguments = args(&["-c", "yes x | head -c 20000"]);
    let mut child = MacOsManagedChild::spawn(&spec(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        Duration::from_secs(5),
    ))
    .unwrap();
    child.wait(Duration::from_secs(5)).unwrap();
    assert!(child.stdout_truncated());
    assert_eq!(child.stdout().len(), 8 * 1024);
}
