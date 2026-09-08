macro_rules! emit { () => { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); } }
pub(crate) use emit as alias;
pub fn production() { alias!(); }
