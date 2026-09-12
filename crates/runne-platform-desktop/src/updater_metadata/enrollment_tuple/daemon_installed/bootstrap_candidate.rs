//! Authenticated V3 package facts for runner bootstrap, never qualification.

use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use runne_macos_process_identity::MacOsLocalPeerProcessIdentity;

use super::capability::authenticated_desktop_matches;
use super::{
    CurrentStagedDaemonIdentity, DaemonIdentityVerifier, NativeEnrollmentArtifactPathsV1,
    NativeEnrollmentTupleAdmission, compiled_policy, refresh_retained_admission_at,
    verified_admission,
};

/// Sealed raw V3 package tuple bound to the current authenticated desktop peer.
///
/// It is not a release qualification, credential authority, or mutation capability.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationBootstrapCandidate;
///
/// let _ = VerifiedInstalledQualificationBootstrapCandidate {};
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationBootstrapCandidate;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<VerifiedInstalledQualificationBootstrapCandidate>();
/// ```
pub struct VerifiedInstalledQualificationBootstrapCandidate {
    peer: MacOsLocalPeerProcessIdentity,
    paths: NativeEnrollmentArtifactPathsV1,
    admission: NativeEnrollmentTupleAdmission,
    runtime_root: PathBuf,
}

impl VerifiedInstalledQualificationBootstrapCandidate {
    /// Loads a signed, installed V3 tuple from a kernel-authenticated desktop peer.
    #[must_use]
    pub fn load_current_for_authenticated_desktop_peer(
        canonical_runtime_root: &Path,
        stream: &UnixStream,
    ) -> Option<Self> {
        if std::fs::canonicalize(canonical_runtime_root)
            .ok()?
            .as_path()
            != canonical_runtime_root
        {
            return None;
        }
        let (paths, peer) =
            NativeEnrollmentArtifactPathsV1::resolve_installed_from_authenticated_desktop_peer(
                stream,
            )
            .ok()?;
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let admission = verified_admission(canonical_runtime_root, &paths, &trust, &policy)?;
        bootstrap_tuple(&admission)?;
        let identity = CurrentStagedDaemonIdentity::new(canonical_runtime_root);
        if !authenticated_desktop_matches(&paths, &admission, &peer, stream)
            || !identity.confirm(&paths, &admission)
        {
            return None;
        }
        let fresh = refresh_retained_admission_at(
            canonical_runtime_root,
            &paths,
            &trust,
            &policy,
            &admission,
            now()?,
        )?;
        if bootstrap_tuple(&fresh).is_none()
            || !authenticated_desktop_matches(&paths, &fresh, &peer, stream)
            || !identity.confirm(&paths, &fresh)
            || peer.revalidate_same_peer(stream).is_err()
        {
            return None;
        }
        Some(Self {
            peer,
            paths,
            admission: fresh,
            runtime_root: canonical_runtime_root.to_path_buf(),
        })
    }

    /// Revalidates retained package, peer, journals, and staged daemon before use.
    #[must_use]
    pub fn revalidate_for_authenticated_desktop_peer(self, stream: &UnixStream) -> Option<Self> {
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let fresh = refresh_retained_admission_at(
            &self.runtime_root,
            &self.paths,
            &trust,
            &policy,
            &self.admission,
            now()?,
        )?;
        if bootstrap_tuple(&fresh).is_none()
            || !authenticated_desktop_matches(&self.paths, &fresh, &self.peer, stream)
            || !CurrentStagedDaemonIdentity::new(&self.runtime_root).confirm(&self.paths, &fresh)
            || self.peer.revalidate_same_peer(stream).is_err()
        {
            return None;
        }
        Some(Self {
            admission: fresh,
            ..self
        })
    }

    /// Returns the retained signed V3 candidate digest after authenticated loading.
    #[must_use]
    pub fn candidate_sha256(&self) -> Option<[u8; 32]> {
        bootstrap_tuple(&self.admission).map(|(candidate, _)| candidate)
    }

    /// Returns the retained signed V3 raw tuple digest after authenticated loading.
    #[must_use]
    pub fn raw_v3_tuple_sha256(&self) -> Option<[u8; 32]> {
        bootstrap_tuple(&self.admission).map(|(_, raw)| raw)
    }
}

fn bootstrap_tuple(admission: &NativeEnrollmentTupleAdmission) -> Option<([u8; 32], [u8; 32])> {
    if !matches!(
        admission.qualification(),
        crate::NativeEnrollmentQualification::Unqualified
    ) {
        return None;
    }
    let candidate = admission.raw_v3_candidate_sha256?;
    let raw = admission.raw_v3_tuple_sha256?;
    (candidate != [0; 32] && raw != [0; 32]).then_some((candidate, raw))
}

fn now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::super::capability::qualified_admission;
    use super::bootstrap_tuple;

    #[test]
    fn raw_v3_tuple_is_usable_without_a_qualification_row() {
        let mut target = crate::tests::updater_enrollment_macos_identity::target();
        target.native_enrollment_tuple = None;
        let measured = crate::tests::updater_enrollment_v3_fixture::macos_tuple_v3(&target, '4');
        target.native_enrollment_tuple_v3 = Some(measured.clone());
        let verified = crate::tests::updater_enrollment_macos_identity::verify_target(&target)
            .expect("verified update");
        let admission = verified
            .admit_native_enrollment_v3(&measured)
            .expect("raw V3 admission");
        assert!(matches!(
            admission.qualification(),
            crate::NativeEnrollmentQualification::Unqualified
        ));
        assert!(qualified_admission(&admission).is_none());
        assert_eq!(
            bootstrap_tuple(&admission),
            Some((
                verified
                    .native_enrollment_tuple_v3()
                    .expect("tuple")
                    .candidate_digest(),
                verified
                    .native_enrollment_tuple_v3()
                    .expect("tuple")
                    .tuple_digest(),
            ))
        );

        let mut rejected = admission;
        rejected.raw_v3_candidate_sha256 = None;
        assert_eq!(bootstrap_tuple(&rejected), None);

        rejected.raw_v3_candidate_sha256 = Some([0; 32]);
        assert_eq!(bootstrap_tuple(&rejected), None);

        rejected.raw_v3_candidate_sha256 = Some([1; 32]);
        rejected.raw_v3_tuple_sha256 = Some([0; 32]);
        assert_eq!(bootstrap_tuple(&rejected), None);

        rejected.raw_v3_tuple_sha256 = None;
        assert_eq!(bootstrap_tuple(&rejected), None, "V2 has no raw V3 tuple");

        let row = crate::NativeEnrollmentQualificationRowV1::new_v3(
            &target,
            &measured,
            "9".repeat(64),
            99,
            200,
        )
        .expect("qualification row");
        target.native_enrollment_tuple_v3 = Some(
            measured
                .clone()
                .with_qualification(&target, row)
                .expect("qualified tuple"),
        );
        let qualified = crate::tests::updater_enrollment_macos_identity::verify_target(&target)
            .expect("verified qualified update")
            .admit_native_enrollment_v3(&measured)
            .expect("qualified admission");
        assert!(matches!(
            qualified.qualification(),
            crate::NativeEnrollmentQualification::Qualified(_)
        ));
        assert_eq!(bootstrap_tuple(&qualified), None);
    }
}
