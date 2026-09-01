#![cfg(target_os = "macos")]

use runne_macos_process_identity::{
    MacOsPackagedWriterObservationError, MacOsPendingPackagedWriterObservationV1,
    MacOsUntrustedWriterEndpointHandoffV1,
};

#[test]
fn observation_error_is_the_closed_two_case_contract() {
    assert_eq!(
        format!("{:?}", MacOsPackagedWriterObservationError::Rejected),
        "Rejected"
    );
    assert_eq!(
        format!("{:?}", MacOsPackagedWriterObservationError::Unavailable),
        "Unavailable"
    );
}

#[test]
fn consuming_entry_has_the_only_pending_result() {
    let entry: fn(
        MacOsUntrustedWriterEndpointHandoffV1,
    ) -> Result<
        MacOsPendingPackagedWriterObservationV1,
        MacOsPackagedWriterObservationError,
    > = MacOsUntrustedWriterEndpointHandoffV1::observe_pending_packaged_writer;
    let _ = entry;
}
