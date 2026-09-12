use super::super::enrollment_daemon_installed::CurrentStagedDaemonIdentity;
use super::{
    DaemonIdentityVerifier, DaemonVerificationInput, MacOsLocalPeerProcessIdentity,
    NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission, Path, UnixStream,
    VerifiedDaemonNativeEnrollmentPrepare, compiled_policy, desktop_peer_digest,
    refresh_retained_admission_at, verify_with_final,
};
use runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3;

impl VerifiedDaemonNativeEnrollmentPrepare {
    /// Fresh native verification for an already authenticated current V3 round.
    /// The caller must separately verify live session and installation ownership.
    /// No V2 projection or retained claim authorization is used.
    #[must_use]
    pub fn verify_and_measure_current_v3_peer(
        profile_directory: &Path,
        canonical_runtime_root: &Path,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        stream: &UnixStream,
    ) -> Option<crate::VerifiedInstalledEnrollmentMeasurementFacts> {
        let policy = compiled_policy()?;
        let (paths, peer) =
            NativeEnrollmentArtifactPathsV1::resolve_installed_from_authenticated_desktop_peer(
                stream,
            )
            .ok()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let identity = CurrentStagedDaemonIdentity::new(canonical_runtime_root);
        let binding = owned.enrollment_binding();
        let admission = verify_with_final(
            &DaemonVerificationInput {
                profile_directory,
                paths: &paths,
                trust: &trust,
                policy: &policy,
                release_tuple_digest: *binding.release_tuple_digest(),
                qualification_binding_digest: *binding.qualification_binding_digest(),
            },
            &identity,
            || {},
            |admission| round_peer_matches(&paths, admission, &peer, owned, stream),
        )?;
        let verified = Self::peer_bound(
            peer,
            *binding.desktop_peer_binding_digest(),
            paths,
            admission,
            profile_directory.to_path_buf(),
            canonical_runtime_root.to_path_buf(),
        );
        let facts =
            crate::VerifiedInstalledEnrollmentMeasurementFacts::from_revalidated(&verified)?;
        let paths = verified.paths.as_ref()?;
        let admission = verified.admission.as_ref()?;
        let peer = verified.peer.as_ref()?;
        // Measurement/journal reads do not replace the final native and metadata checks.
        refresh_retained_admission_at(
            profile_directory,
            paths,
            &trust,
            &policy,
            admission,
            now()?,
        )?;
        if !CurrentStagedDaemonIdentity::new(canonical_runtime_root).confirm(paths, admission)
            || !round_peer_matches(paths, admission, peer, owned, stream)
        {
            return None;
        }
        Some(facts)
    }
}

fn now() -> Option<u64> {
    Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs(),
    )
}

fn round_peer_matches(
    paths: &NativeEnrollmentArtifactPathsV1,
    admission: &NativeEnrollmentTupleAdmission,
    peer: &MacOsLocalPeerProcessIdentity,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    stream: &UnixStream,
) -> bool {
    let Some(identity) = admission.macos_desktop_code_identity.as_ref() else {
        return false;
    };
    let Some(now) = now() else {
        return false;
    };
    peer.revalidate_same_peer(stream).is_ok()
        && round_claims_match(admission, peer, owned, now)
        && paths
            .confirm_peer_macos_desktop(peer.pid(), admission.desktop_sha256, identity)
            .is_ok()
        && peer.revalidate_same_peer(stream).is_ok()
}

fn round_claims_match(
    admission: &NativeEnrollmentTupleAdmission,
    peer: &MacOsLocalPeerProcessIdentity,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    now: u64,
) -> bool {
    let binding = owned.enrollment_binding();
    admission.daemon_sha256 == *owned.executable().executable_sha256()
        && admission.release_tuple_sha256 == *binding.release_tuple_digest()
        && admission.qualification.matches_exact(
            *binding.release_tuple_digest(),
            *binding.qualification_binding_digest(),
            now,
        )
        && desktop_peer_digest(
            admission.release_tuple_sha256,
            admission.desktop_sha256,
            peer.process_start_digest(),
            peer.euid(),
            *owned.launch_authority_id(),
            *owned.desktop_host_instance_id(),
            binding.desktop_supervisor_generation(),
        ) == *binding.desktop_peer_binding_digest()
}

#[cfg(test)]
#[path = "round/tests.rs"]
mod tests;
