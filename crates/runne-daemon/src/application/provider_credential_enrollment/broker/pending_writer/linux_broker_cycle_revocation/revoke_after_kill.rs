use super::fixture::DurableFixture;
use super::kill_fixture::PostDeleteKillFixture;
use super::native::poll_absence;
use super::writer::start_writer;
use super::*;

pub(super) fn revoke_through_real_writer_after_delete_kill(
    f: &mut DurableFixture,
    binary: &std::path::Path,
    service: &str,
    kill_fixture: &PostDeleteKillFixture,
) -> u32 {
    let mut started = start_writer(f, binary, false);
    let channel = started.owned.0.as_mut().unwrap();
    let head = f
        .store()
        .lifecycle_snapshot(f.operation.provider())
        .unwrap();
    let accepted = f
        .store()
        .accept_cleanup_recovery(CredentialCleanupRecoveryRequest::new(
            f.operation.operation_id(),
            f.operation.installation_owner_id(),
            f.measurements.release_manifest_digest([9; 32]).unwrap(),
            f.measurements.protected_session_id([17; 32]).unwrap(),
            f.measurements.desktop_supervisor_generation(8).unwrap(),
            7,
            head.lifecycle_revision(),
            head.fence(),
            f.measurements
                .continuation_binding_digest([45; 32])
                .unwrap(),
            60,
        ))
        .unwrap();
    let context = f
        .broker
        .claim_issue_context(
            started.facts.clone(),
            started.channel_binding,
            f.continuation,
            7,
            8,
        )
        .unwrap();
    let receipt = f
        .broker
        .issue_ticket(accepted, f.continuation, &context, 60, f.store(), channel)
        .unwrap();
    let mut claimed = f
        .broker
        .claim_ticket_from_channel(
            receipt,
            f.continuation,
            7,
            8,
            started.facts,
            f.store(),
            channel,
        )
        .unwrap();
    assert!(claimed.take_secret_relay().unwrap().is_none());
    f.broker
        .release_control_only_effect(&claimed, f.operation.operation_id(), f.store(), channel)
        .unwrap();
    poll_absence(service);
    let marker = kill_fixture.root().join("post-delete.marker");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.is_file() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let pid: u32 = std::fs::read_to_string(marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let live_exe = std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
    let launched_exe = std::fs::metadata(binary).unwrap();
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        (live_exe.dev(), live_exe.ino()),
        (launched_exe.dev(), launched_exe.ino())
    );
    // The marker is the barrier. Terminate and reap through the daemon's
    // retained pidfd while the writer is still blocked before its ACK.
    started
        .owned
        .0
        .take()
        .unwrap()
        .terminate_exact_writer()
        .unwrap();
    pid
}
