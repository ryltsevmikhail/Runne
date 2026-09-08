struct Holder(runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1);
fn production(holder: Holder, release: &runne_api::VerifiedSignedInstalledReleaseV2) { let Holder(pending) = holder; let _ = pending.verify_exact(release); }
