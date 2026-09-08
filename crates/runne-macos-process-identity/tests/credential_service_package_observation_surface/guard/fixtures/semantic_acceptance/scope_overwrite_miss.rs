struct Holder { pending: runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 }
struct Different; struct Other { pending: Different }
fn production(holder: Holder, release: &runne_api::VerifiedSignedInstalledReleaseV2) { let _ = holder.pending.verify_exact(release); }
fn later(holder: Other) { drop(holder); }
