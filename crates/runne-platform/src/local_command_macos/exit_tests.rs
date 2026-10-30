use super::*;
use std::process::Command;

#[test]
fn exits_are_classified_with_their_code() {
    let status = Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .status()
        .unwrap();
    let observation = LinuxLeaderExitObservationV1::from_status(status);
    assert_eq!(
        observation.kind(),
        LinuxLeaderExitKindV1::Exited { code: 7 }
    );
    assert_eq!(observation.legacy_exit_code(), 7);
}

#[test]
fn signals_are_classified_with_their_number() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let status = child.wait().unwrap();
    let observation = LinuxLeaderExitObservationV1::from_status(status);
    assert_eq!(
        observation.kind(),
        LinuxLeaderExitKindV1::Signaled {
            signal: libc::SIGTERM,
            core_dumped: false,
        }
    );
    assert_eq!(observation.legacy_exit_code(), 128 + libc::SIGTERM);
}
