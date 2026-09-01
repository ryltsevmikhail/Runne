#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};

use runne_native_enrollment_authority::{
    PendingPinnedProviderCredentialWriterSessionV1,
    UntrustedProviderCredentialWriterEndpointHandoffV1,
};

const PROBE_ENV: &str = "RUNNE_AUTHORITY_HANDOFF_PROBE";

#[test]
fn handoff_exposes_one_consuming_pinned_observation_transition() {
    let observe: fn(
        UntrustedProviderCredentialWriterEndpointHandoffV1,
    ) -> Result<
        PendingPinnedProviderCredentialWriterSessionV1,
        runne_macos_process_identity::MacOsPackagedWriterObservationError,
    > = UntrustedProviderCredentialWriterEndpointHandoffV1::observe_current_pinned_writer_session;
    let _ = observe;
}

#[test]
fn missing_stdin_socket_is_rejected_without_authority() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "receive_from_stdin_probe", "--nocapture"])
        .env(PROBE_ENV, "1")
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "probe must observe a typed ingress error");
}

#[test]
fn receive_from_stdin_probe() {
    if std::env::var_os(PROBE_ENV).is_none() {
        return;
    }
    assert!(UntrustedProviderCredentialWriterEndpointHandoffV1::receive_from_stdin().is_err());
}
