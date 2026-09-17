//! Release qualification for capability selection, never request authority.

use super::{
    CurrentStagedDaemonIdentity, DaemonIdentityVerifier, NativeEnrollmentArtifactPathsV1,
    NativeEnrollmentTupleAdmission, compiled_policy, refresh_retained_admission_at,
    verified_admission,
};
use std::path::{Path, PathBuf};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_macos_process_identity::MacOsLocalPeerProcessIdentity;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::unix::net::UnixStream;

/// Opaque proof that the current daemon belongs to a qualified installed release.
/// It grants no peer, session, credential-store, or mutation authority.
pub struct VerifiedInstalledEnrollmentCapability {
    _private: (),
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    retained: Option<RetainedAuthenticatedDesktopCapability>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct RetainedAuthenticatedDesktopCapability {
    peer: MacOsLocalPeerProcessIdentity,
    paths: NativeEnrollmentArtifactPathsV1,
    admission: NativeEnrollmentTupleAdmission,
    profile_directory: PathBuf,
    runtime_root: PathBuf,
}

impl VerifiedInstalledEnrollmentCapability {
    /// Verifies a staged daemon against a kernel-authenticated desktop peer.
    ///
    /// Package paths come only from `stream`; `canonical_runtime_root` must be
    /// the owner-private root accepted with the protected launch request.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[must_use]
    pub fn load_current_for_authenticated_desktop_peer(
        profile_directory: &Path,
        canonical_runtime_root: &Path,
        stream: &UnixStream,
    ) -> Option<Self> {
        let (paths, peer) =
            NativeEnrollmentArtifactPathsV1::resolve_installed_from_authenticated_desktop_peer(
                stream,
            )
            .ok()?;
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let admission = verified_admission(profile_directory, &paths, &trust, &policy)?;
        qualified_admission(&admission)?;
        let identity = CurrentStagedDaemonIdentity::new(canonical_runtime_root);
        if !authenticated_desktop_matches(&paths, &admission, &peer, stream)
            || !identity.confirm(&paths, &admission)
        {
            return None;
        }
        let fresh = refresh_retained_admission_at(
            profile_directory,
            &paths,
            &trust,
            &policy,
            &admission,
            now()?,
        )?;
        if qualified_admission(&fresh).is_none()
            || !authenticated_desktop_matches(&paths, &fresh, &peer, stream)
            || !identity.confirm(&paths, &fresh)
            || peer.revalidate_same_peer(stream).is_err()
        {
            return None;
        }
        Some(Self {
            _private: (),
            retained: Some(RetainedAuthenticatedDesktopCapability {
                peer,
                paths,
                admission: fresh,
                profile_directory: profile_directory.to_path_buf(),
                runtime_root: canonical_runtime_root.to_path_buf(),
            }),
        })
    }

    /// Rechecks the retained peer, journal, package and staged self for a later
    /// protected startup phase.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[must_use]
    pub fn revalidate_for_authenticated_desktop_peer(&self, stream: &UnixStream) -> bool {
        let Some(retained) = self.retained.as_ref() else {
            return false;
        };
        let Some(policy) = compiled_policy() else {
            return false;
        };
        let Some(trust) = crate::CompiledUpdateTrustRootV2::load()
            .map(runne_api::CompiledUpdateTrustRootV2::into_trust_root)
        else {
            return false;
        };
        let Some(now) = now() else {
            return false;
        };
        let Some(fresh) = refresh_retained_admission_at(
            &retained.profile_directory,
            &retained.paths,
            &trust,
            &policy,
            &retained.admission,
            now,
        ) else {
            return false;
        };
        let identity = CurrentStagedDaemonIdentity::new(&retained.runtime_root);
        qualified_admission(&fresh).is_some()
            && authenticated_desktop_matches(&retained.paths, &fresh, &retained.peer, stream)
            && identity.confirm(&retained.paths, &fresh)
            && retained.peer.revalidate_same_peer(stream).is_ok()
    }

    pub(crate) fn load_for_desktop(profile_directory: &Path) -> Option<Self> {
        let paths = NativeEnrollmentArtifactPathsV1::resolve_installed().ok()?;
        Self::load_paths(profile_directory, &paths, &CurrentDesktopIdentity)
    }

    fn load_paths(
        profile_directory: &Path,
        paths: &NativeEnrollmentArtifactPathsV1,
        identity: &impl DaemonIdentityVerifier,
    ) -> Option<Self> {
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let admitted = verified_admission(profile_directory, paths, &trust, &policy)?;
        qualified_admission(&admitted)?;
        if !identity.confirm(paths, &admitted) {
            return None;
        }
        let fresh = refresh_retained_admission_at(
            profile_directory,
            paths,
            &trust,
            &policy,
            &admitted,
            now()?,
        )?;
        (qualified_admission(&fresh).is_some() && identity.confirm(paths, &fresh)).then_some(Self {
            _private: (),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            retained: None,
        })
    }
}

struct CurrentDesktopIdentity;

impl DaemonIdentityVerifier for CurrentDesktopIdentity {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool {
        admission
            .macos_desktop_code_identity
            .as_ref()
            .is_some_and(|identity| {
                paths
                    .confirm_current_macos_desktop(admission.desktop_sha256, identity)
                    .is_ok()
            })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn authenticated_desktop_matches(
    paths: &NativeEnrollmentArtifactPathsV1,
    admission: &NativeEnrollmentTupleAdmission,
    peer: &MacOsLocalPeerProcessIdentity,
    stream: &UnixStream,
) -> bool {
    let Some(identity) = admission.macos_desktop_code_identity.as_ref() else {
        return false;
    };
    peer.revalidate_same_peer(stream).is_ok()
        && paths
            .confirm_peer_macos_desktop(peer.pid(), admission.desktop_sha256, identity)
            .is_ok()
        && peer.revalidate_same_peer(stream).is_ok()
}

pub(super) fn qualified_admission(admission: &NativeEnrollmentTupleAdmission) -> Option<()> {
    admission.raw_v3_tuple_sha256?;
    admission.qualification_candidate_v3.as_ref()?;
    admission.candidate_source_sha256?;
    admission.target_manifest_sha256?;
    admission.desktop_credential_service_configuration().ok()?;
    admission.runtime_credential_service_configuration().ok()?;
    admission.writer_credential_service_configuration().ok()?;
    let qualification = admission
        .qualification
        .retained_qualification_binding_digest()?;
    admission
        .qualification
        .matches_exact(admission.release_tuple_sha256, qualification, now()?)
        .then_some(())
}

fn now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl crate::UpdateCoordinator {
    /// Opens local installed admission without requiring a remote feed endpoint.
    /// Trust and release identity are verified from the running signed package.
    #[must_use]
    pub fn for_current_installed_release(profile_directory: &Path) -> Option<Self> {
        let paths = NativeEnrollmentArtifactPathsV1::resolve_installed().ok()?;
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let admission = verified_admission(profile_directory, &paths, &trust, &policy)?;
        qualified_admission(&admission)?;
        if !CurrentDesktopIdentity.confirm(&paths, &admission) {
            return None;
        }
        let measured = paths.measure().ok()?;
        let (runtime_digest, bundle_sha256) = measured.daemon_and_contract_digests();
        let coordinator = Self::new(
            trust,
            crate::UpdateTargetBindingConfig {
                product_id: "com.runne.desktop".into(),
                platform: "macos".into(),
                arch: "arm64".into(),
                min_os: "macos-13".into(),
                profile_id: policy.profile_id.into(),
                bundle_sha256: bundle_sha256.into(),
                runtime_version: policy.runtime_version.into(),
                runtime_digest: runtime_digest.into(),
                channel: policy.channel.into(),
            },
            profile_directory,
        )
        .ok()?;
        coordinator.prepare_installed_native_enrollment().ok()??;
        Some(coordinator)
    }
}
