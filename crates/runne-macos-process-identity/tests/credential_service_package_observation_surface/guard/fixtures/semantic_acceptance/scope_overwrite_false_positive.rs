struct Holder { pending: runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 }
struct Different; impl Different { fn verify_exact(self, _: &runne_api::VerifiedSignedInstalledReleaseV2) {} }
struct Other { pending: Different }
fn production(holder: Other, release: &runne_api::VerifiedSignedInstalledReleaseV2) { holder.pending.verify_exact(release); }
fn later(holder: Holder) { drop(holder); }
