#![cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
use std::path::Path;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::path::PathBuf;

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission};

mod measurement_facts;
pub use measurement_facts::VerifiedInstalledEnrollmentMeasurementFacts;

/// Opaque evidence bound to one exact daemon prepare claim.
///
/// The evidence is move-only so one verification cannot authorize two prepares.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare;
///
/// let _ = VerifiedDaemonNativeEnrollmentPrepare { _private: () };
/// ```
pub struct VerifiedDaemonNativeEnrollmentPrepare {
    _private: (),
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) peer: Option<runne_macos_process_identity::MacOsLocalPeerProcessIdentity>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) peer_binding: [u8; 32],
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) paths: Option<NativeEnrollmentArtifactPathsV1>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) admission: Option<NativeEnrollmentTupleAdmission>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) profile_directory: Option<PathBuf>,
}

impl VerifiedDaemonNativeEnrollmentPrepare {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) const fn peer_bound(
        peer: runne_macos_process_identity::MacOsLocalPeerProcessIdentity,
        peer_binding: [u8; 32],
        paths: NativeEnrollmentArtifactPathsV1,
        admission: NativeEnrollmentTupleAdmission,
        profile_directory: PathBuf,
    ) -> Self {
        Self {
            _private: (),
            peer: Some(peer),
            peer_binding,
            paths: Some(paths),
            admission: Some(admission),
            profile_directory: Some(profile_directory),
        }
    }

    #[cfg(test)]
    const fn unbound_for_internal_test() -> Self {
        Self {
            _private: (),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            peer: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            peer_binding: [0; 32],
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            paths: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            admission: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            profile_directory: None,
        }
    }
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) struct DaemonEnrollmentPolicy<'a> {
    pub(super) profile_id: &'a str,
    pub(super) runtime_version: &'a str,
    pub(super) channel: &'a str,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) struct DaemonVerificationInput<'a> {
    pub(super) profile_directory: &'a Path,
    pub(super) paths: &'a NativeEnrollmentArtifactPathsV1,
    pub(super) trust: &'a crate::UpdateTrustRootV2,
    pub(super) policy: &'a DaemonEnrollmentPolicy<'a>,
    pub(super) release_tuple_digest: [u8; 32],
    pub(super) qualification_binding_digest: [u8; 32],
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) trait DaemonIdentityVerifier {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool;
}

#[cfg(test)]
fn verify_with<I, F>(
    input: &DaemonVerificationInput<'_>,
    identity: &I,
    between_phases: F,
) -> Option<VerifiedDaemonNativeEnrollmentPrepare>
where
    I: DaemonIdentityVerifier,
    F: FnOnce(),
{
    verify_with_final(input, identity, between_phases, |_| true)?;
    Some(VerifiedDaemonNativeEnrollmentPrepare::unbound_for_internal_test())
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn verify_with_final<I, F, G>(
    input: &DaemonVerificationInput<'_>,
    identity: &I,
    between_phases: F,
    final_check: G,
) -> Option<NativeEnrollmentTupleAdmission>
where
    I: DaemonIdentityVerifier,
    F: FnOnce(),
    G: FnOnce(&NativeEnrollmentTupleAdmission) -> bool,
{
    let _ = verified_admission(input.profile_directory, input.paths, input.trust, input.policy)?;
    between_phases();
    let admission = verified_admission(input.profile_directory, input.paths, input.trust, input.policy)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    (identity.confirm(input.paths, &admission)
        && admission.release_tuple_sha256 == input.release_tuple_digest
        && admission.qualification.matches_exact(
            input.release_tuple_digest,
            input.qualification_binding_digest,
            now,
        ) && final_check(&admission))
    .then_some(admission)
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn verified_admission(
    profile_directory: &Path,
    paths: &NativeEnrollmentArtifactPathsV1,
    trust: &crate::UpdateTrustRootV2,
    policy: &DaemonEnrollmentPolicy<'_>,
) -> Option<NativeEnrollmentTupleAdmission> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    verified_admission_at(profile_directory, paths, trust, policy, now)
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn refresh_retained_admission_at(
    profile_directory: &Path,
    paths: &NativeEnrollmentArtifactPathsV1,
    trust: &crate::UpdateTrustRootV2,
    policy: &DaemonEnrollmentPolicy<'_>,
    retained: &NativeEnrollmentTupleAdmission,
    now: u64,
) -> Option<NativeEnrollmentTupleAdmission> {
    let fresh = verified_admission_at(profile_directory, paths, trust, policy, now)?;
    (fresh == *retained).then_some(fresh)
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
fn verified_admission_at(
    profile_directory: &Path,
    paths: &NativeEnrollmentArtifactPathsV1,
    trust: &crate::UpdateTrustRootV2,
    policy: &DaemonEnrollmentPolicy<'_>,
    now: u64,
) -> Option<NativeEnrollmentTupleAdmission> {
    use crate::{
        UpdateInstallState, UpdateJournal, UpdateTargetV2Binding, UpdateTrustJournal,
        verify_update_v2,
    };
    use crate::updater_installed_metadata::InstalledUpdateMetadataJournal;

    let artifacts = paths.measure().ok()?;
    let (runtime_digest, bundle_sha256) = artifacts.daemon_and_contract_digests();
    let updates = profile_directory.join("updates");
    let record = UpdateJournal::new(updates.join("install-state.json")).read().ok()??;
    let trust_state = UpdateTrustJournal::new(updates.join("trust-state.json")).read().ok()??;
    let (metadata, metadata_binding) =
        InstalledUpdateMetadataJournal::new(updates.join("installed-metadata.json")).read().ok()??;
    if record.state != UpdateInstallState::Committed
        || record.legacy_unbound
        || record.metadata_sha256.as_deref() != Some(&metadata_binding)
        || record.version != trust_state.installed_version
        || metadata.root.version != trust_state.root_version
        || metadata.snapshot.version != trust_state.snapshot_version
    {
        return None;
    }
    let binding = UpdateTargetV2Binding {
        product_id: "com.runne.desktop",
        platform: "macos",
        arch: "arm64",
        min_os: "macos-13",
        profile_id: policy.profile_id,
        bundle_sha256,
        runtime_version: policy.runtime_version,
        runtime_digest,
        channel: policy.channel,
    };
    let verified = verify_update_v2(
        &metadata,
        trust,
        &binding,
        now,
        &trust_state.installed_version,
        &trust_state.rollback_floor,
    )
    .ok()?;
    (verified.target().version == record.version
        && verified.target().artifact_sha256 == record.artifact_sha256)
    .then(|| verified.admit_native_enrollment(&artifacts))?
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) struct CurrentDaemonIdentity;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl DaemonIdentityVerifier for CurrentDaemonIdentity {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool {
        admission.macos_daemon_code_identity.as_ref().is_some_and(|identity| {
            paths
                .confirm_current_signed_daemon(admission.daemon_sha256, identity)
                .is_ok()
        })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn compiled_policy() -> Option<DaemonEnrollmentPolicy<'static>> {
    Some(DaemonEnrollmentPolicy {
        profile_id: option_env!("RUNNE_UPDATE_PROFILE_ID").filter(|value| !value.is_empty())?,
        runtime_version: option_env!("RUNNE_UPDATE_RUNTIME_VERSION").filter(|value| !value.is_empty())?,
        channel: option_env!("RUNNE_UPDATE_CHANNEL").filter(|value| !value.is_empty())?,
    })
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_installed/tests.rs"]
pub(super) mod tests;
