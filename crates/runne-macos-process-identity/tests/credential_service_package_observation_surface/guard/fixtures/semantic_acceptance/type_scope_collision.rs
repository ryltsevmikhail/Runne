mod target_scope { type Pending = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1; }
mod unrelated { struct Pending; impl Pending { fn capture_current() -> Self { Self } } pub fn production() { let _ = Pending::capture_current(); } }
