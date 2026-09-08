struct Holder { pending: runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 }
fn production(Holder { pending }: Holder, release: &runne_api::VerifiedSignedInstalledReleaseV2) { let _ = pending.verify_exact(release); }
