#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::{os::unix::net::UnixStream, path::Path};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_api::VerifiedProtectedCredentialEnrollmentPrepareV2;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_macos_process_identity::MacOsLocalPeerProcessIdentity;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::{
    NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission,
    VerifiedDaemonNativeEnrollmentPrepare,
    enrollment_daemon_installed::{
        CurrentDaemonIdentity, DaemonIdentityVerifier, DaemonVerificationInput, compiled_policy,
        refresh_retained_admission_at, verify_with_final,
    },
    enrollment_desktop_peer_claim::desktop_peer_digest,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl VerifiedDaemonNativeEnrollmentPrepare {
    /// Authenticates one exact local desktop peer and its V2 prepare claims.
    #[must_use]
    pub fn verify_current_for_peer(
        profile_directory: &Path,
        claims: &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
        stream: &UnixStream,
    ) -> Option<Self> {
        let policy = compiled_policy()?;
        let paths = NativeEnrollmentArtifactPathsV1::resolve_installed_from_current_daemon().ok()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let peer = MacOsLocalPeerProcessIdentity::capture(stream).ok()?;
        let admission = verify_with_final(
            &DaemonVerificationInput {
                profile_directory,
                paths: &paths,
                trust: &trust,
                policy: &policy,
                release_tuple_digest: *claims.release_tuple_digest(),
                qualification_binding_digest: *claims.qualification_binding_digest(),
            },
            &CurrentDaemonIdentity,
            || {},
            |admission| peer_matches_claims(&paths, admission, claims, &peer, stream),
        )?;
        Some(Self::peer_bound(
            peer,
            *claims.desktop_peer_binding_digest(),
            paths,
            admission,
            profile_directory.to_path_buf(),
        ))
    }

    /// Consumes the token unless the original kernel peer still owns `stream`.
    #[must_use]
    pub fn revalidate_current_peer(self, stream: &UnixStream) -> Option<Self> {
        let peer = self.peer.as_ref()?;
        let paths = self.paths.as_ref()?;
        let admission = self.admission.as_ref()?;
        let profile_directory = self.profile_directory.as_ref()?;
        let identity = admission.macos_desktop_code_identity.as_ref()?;
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        if self.peer_binding == [0; 32]
            || peer.revalidate_same_peer(stream).is_err()
            || refresh_retained_admission_at(
                profile_directory,
                paths,
                &trust,
                &policy,
                admission,
                now,
            )
            .is_none()
            || !CurrentDaemonIdentity.confirm(paths, admission)
            || paths
                .confirm_peer_macos_desktop(peer.pid(), admission.desktop_sha256, identity)
                .is_err()
            || peer.revalidate_same_peer(stream).is_err()
        {
            return None;
        }
        Some(self)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn peer_matches_claims(
    paths: &NativeEnrollmentArtifactPathsV1,
    admission: &NativeEnrollmentTupleAdmission,
    claims: &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
    peer: &MacOsLocalPeerProcessIdentity,
    stream: &UnixStream,
) -> bool {
    let Some(identity) = admission.macos_desktop_code_identity.as_ref() else {
        return false;
    };
    if paths
        .confirm_peer_macos_desktop(peer.pid(), admission.desktop_sha256, identity)
        .is_err()
        || peer.revalidate_same_peer(stream).is_err()
    {
        return false;
    }
    let binding = desktop_peer_digest(
        admission.release_tuple_sha256,
        admission.desktop_sha256,
        peer.process_start_digest(),
        peer.euid(),
        *claims.launch_authority_id(),
        *claims.desktop_host_instance_id(),
        claims.desktop_supervisor_generation(),
    );
    binding == *claims.desktop_peer_binding_digest()
        && peer.revalidate_same_peer(stream).is_ok()
        && paths
            .confirm_peer_macos_desktop(peer.pid(), admission.desktop_sha256, identity)
            .is_ok()
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    #[test]
    fn revalidation_brackets_guest_code_and_rooted_vnode_checks_with_peer_checks() {
        let source = include_str!("daemon_peer.rs");
        assert!(source.contains(
            "peer.revalidate_same_peer(stream).is_err()\n            || refresh_retained_admission_at("
        ));
        assert!(source.contains(
            "|| !CurrentDaemonIdentity.confirm(paths, admission)\n            || paths\n                .confirm_peer_macos_desktop"
        ));
        assert!(source.contains(
            ".confirm_peer_macos_desktop(peer.pid(), admission.desktop_sha256, identity)\n                .is_err()\n            || peer.revalidate_same_peer(stream).is_err()"
        ));
    }
}
