struct Holder { pending: runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 }
impl Holder { fn production(self, release: &runne_api::VerifiedSignedInstalledReleaseV2) { let _ = self.pending.verify_exact(release); } }
