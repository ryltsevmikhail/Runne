type Capture = fn() -> Result<runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1, runne_macos_process_identity::MacOsCredentialServicePackageObservationError>;
fn production() { let captures: [Capture; 1] = [runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current]; let _ = (captures[0])(); }
