struct Holder { pending: runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 }
fn make(pending: runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1) -> Holder { Holder { pending } }
fn production(pending: runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1, release: &runne_api::VerifiedSignedInstalledReleaseV2) { let holder: Holder = make(pending); let _ = holder.pending.verify_exact(release); }
