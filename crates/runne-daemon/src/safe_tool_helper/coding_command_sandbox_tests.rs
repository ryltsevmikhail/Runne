//! Pipe-level tests for the macOS helper status descriptor.

use super::*;

fn report(bytes: &[u8]) -> Report {
    let (read, write) = status_pipe().expect("status pipe");
    // SAFETY: the test owns both pipe ends and drops each exactly once.
    let mut writer = unsafe { File::from_raw_fd(write) };
    writer.write_all(bytes).expect("write status bytes");
    drop(writer);
    // SAFETY: the read end is owned by this test.
    let mut status = unsafe { File::from_raw_fd(read) };
    protocol::classify(&read_status(&mut status))
}

#[test]
fn reads_a_started_marker() {
    assert_eq!(report(&[protocol::STATUS_READY]), Report::Started);
}

#[test]
fn reads_a_helper_failure() {
    assert_eq!(
        report(&[protocol::STATUS_READY, protocol::STATUS_PROFILE]),
        Report::Failed(protocol::STATUS_PROFILE)
    );
}

#[test]
fn reads_an_empty_descriptor_as_unconfirmed() {
    assert_eq!(report(&[]), Report::Unconfirmed);
}

#[test]
fn maps_helper_statuses_to_tool_errors() {
    assert_eq!(
        helper_error(protocol::STATUS_PROFILE),
        "command_profile_denied"
    );
    assert_eq!(
        helper_error(protocol::STATUS_PANIC),
        "command_helper_aborted"
    );
    assert_eq!(helper_error(0), protocol::PROTOCOL_ERROR);
}
