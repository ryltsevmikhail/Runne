#[path = "enrollment_tuple/measurement.rs"]
mod enrollment_measurement;
pub use enrollment_measurement::MeasuredNativeEnrollmentArtifactsV1;
#[path = "enrollment_tuple/paths.rs"]
mod enrollment_paths;
#[path = "enrollment_tuple/daemon_paths.rs"]
mod enrollment_daemon_paths;
#[path = "enrollment_tuple/desktop_paths.rs"]
mod enrollment_desktop_paths;
#[expect(
    clippy::redundant_pub_crate,
    reason = "fixed package-layout resolution is the remaining production integration step"
)]
pub(crate) use enrollment_paths::NativeEnrollmentArtifactPathsV1;
#[path = "enrollment_tuple/live_daemon.rs"]
mod enrollment_live_daemon;
#[cfg(target_os = "macos")]
pub use enrollment_live_daemon::NativeEnrollmentConfirmationV1;
pub use enrollment_live_daemon::{
    ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment,
};
#[cfg(target_os = "macos")]
#[path = "enrollment_tuple/live_daemon/credential_service.rs"]
mod enrollment_live_daemon_credential_service;
#[path = "enrollment_tuple/desktop_peer_claim.rs"]
mod enrollment_desktop_peer_claim;
#[path = "enrollment_tuple/daemon_installed.rs"]
mod enrollment_daemon_installed;
pub use enrollment_daemon_installed::VerifiedDaemonNativeEnrollmentPrepare;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use enrollment_daemon_installed::{
    QualificationAdmissionError, VerifiedInstalledEnrollmentMeasurementFacts,
    VerifiedInstalledEnrollmentCapability,
};
#[path = "enrollment_tuple/daemon_peer.rs"]
mod enrollment_daemon_peer;

fn matches_installed(
    tuple: &VerifiedSignedNativeEnrollmentTupleV2,
    artifacts: &MeasuredNativeEnrollmentArtifactsV1,
) -> bool {
    decode_digest(&artifacts.desktop_sha256) == Some(tuple.desktop_image_digest())
        && decode_digest(&artifacts.writer_sha256) == Some(tuple.writer_image_digest())
        && decode_digest(&artifacts.daemon_sha256) == Some(tuple.daemon_image_digest())
        && decode_digest(&artifacts.contract_sha256) == Some(tuple.contract_digest())
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}
