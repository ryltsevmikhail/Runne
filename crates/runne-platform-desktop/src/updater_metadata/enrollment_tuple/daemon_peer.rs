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
        CurrentStagedDaemonIdentity, DaemonIdentityVerifier, DaemonVerificationInput,
        compiled_policy, refresh_retained_admission_at, verify_with_final,
    },
    enrollment_desktop_peer_claim::desktop_peer_digest,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl VerifiedDaemonNativeEnrollmentPrepare {
    /// Revalidates and consumes native ownership into claim-eligible installed facts.
    #[must_use]
    pub fn revalidate_and_measure_current_peer_for_claims(
        self,
        stream: &UnixStream,
        claims: &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
    ) -> Option<super::VerifiedInstalledEnrollmentMeasurementFacts> {
        let verified = self.revalidate_current_peer_for_claims(stream, claims)?;
        super::VerifiedInstalledEnrollmentMeasurementFacts::from_revalidated(&verified)
    }

    /// Authenticates one exact local desktop peer and its V2 prepare claims.
    #[must_use]
    pub fn verify_current_for_peer(
        profile_directory: &Path,
        canonical_runtime_root: &Path,
        claims: &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
        stream: &UnixStream,
    ) -> Option<Self> {
        let policy = compiled_policy()?;
        let (paths, peer) =
            NativeEnrollmentArtifactPathsV1::resolve_installed_from_authenticated_desktop_peer(
                stream,
            )
            .ok()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let identity = CurrentStagedDaemonIdentity::new(canonical_runtime_root);
        let admission = verify_with_final(
            &DaemonVerificationInput {
                profile_directory,
                paths: &paths,
                trust: &trust,
                policy: &policy,
                release_tuple_digest: *claims.release_tuple_digest(),
                qualification_binding_digest: *claims.qualification_binding_digest(),
            },
            &identity,
            || {},
            |admission| peer_matches_claims(&paths, admission, claims, &peer, stream),
        )?;
        Some(Self::peer_bound(
            peer,
            *claims.desktop_peer_binding_digest(),
            paths,
            admission,
            profile_directory.to_path_buf(),
            canonical_runtime_root.to_path_buf(),
        ))
    }

    /// Consumes the token unless the original kernel peer still owns `stream`
    /// and its native evidence matches the already authenticated V2 claims.
    #[must_use]
    pub fn revalidate_current_peer_for_claims(
        self,
        stream: &UnixStream,
        claims: &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
    ) -> Option<Self> {
        let peer = self.peer.as_ref()?;
        let paths = self.paths.as_ref()?;
        let admission = self.admission.as_ref()?;
        let profile_directory = self.profile_directory.as_ref()?;
        let runtime_root = self.runtime_root.as_ref()?;
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        if self.peer_binding != *claims.desktop_peer_binding_digest()
            || !retained_claims_match(admission, peer, claims, now)
            || peer.revalidate_same_peer(stream).is_err()
        {
            return None;
        }
        if refresh_retained_admission_at(profile_directory, paths, &trust, &policy, admission, now)
            .is_none()
            || !CurrentStagedDaemonIdentity::new(runtime_root).confirm(paths, admission)
            || peer.revalidate_same_peer(stream).is_err()
            || !peer_matches_claims(paths, admission, claims, peer, stream)
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map_or(0, |duration| duration.as_secs());
    retained_claims_match(admission, peer, claims, now)
        && peer.revalidate_same_peer(stream).is_ok()
        && paths
            .confirm_peer_macos_desktop(peer.pid(), admission.desktop_sha256, identity)
            .is_ok()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retained_claims_match(
    admission: &NativeEnrollmentTupleAdmission,
    peer: &MacOsLocalPeerProcessIdentity,
    claims: &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
    now: u64,
) -> bool {
    admission.release_tuple_sha256 == *claims.release_tuple_digest()
        && admission.qualification.matches_exact(
            *claims.release_tuple_digest(),
            *claims.qualification_binding_digest(),
            now,
        )
        && desktop_peer_digest(
            admission.release_tuple_sha256,
            admission.desktop_sha256,
            peer.process_start_digest(),
            peer.euid(),
            *claims.launch_authority_id(),
            *claims.desktop_host_instance_id(),
            claims.desktop_supervisor_generation(),
        ) == *claims.desktop_peer_binding_digest()
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_peer/claim_tests.rs"]
mod claim_tests;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_peer/round.rs"]
mod round;
