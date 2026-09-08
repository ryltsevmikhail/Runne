macro_rules! expose { () => { let _capture = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current; } }
fn production() { expose!(); }
