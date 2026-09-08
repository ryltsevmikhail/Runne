fn invoke<F: FnOnce() -> Result<runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1, runne_macos_process_identity::MacOsCredentialServicePackageObservationError>>(f: F) { let _ = f(); }
fn production() { invoke(runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current); }
