use std::path::Path;

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission};

/// Opaque evidence bound to one exact daemon prepare claim.
///
/// The evidence is move-only so one verification cannot authorize two prepares.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare;
///
/// let verified = VerifiedDaemonNativeEnrollmentPrepare::verify_current(
///     std::path::Path::new("/"),
///     [1; 32],
///     [2; 32],
/// )
/// .unwrap();
/// let consumed = verified;
/// let replayed = verified;
/// drop((consumed, replayed));
/// ```
pub struct VerifiedDaemonNativeEnrollmentPrepare {
    _private: (),
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
struct DaemonEnrollmentPolicy<'a> {
    profile_id: &'a str,
    runtime_version: &'a str,
    channel: &'a str,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
struct DaemonVerificationInput<'a> {
    profile_directory: &'a Path,
    paths: &'a NativeEnrollmentArtifactPathsV1,
    trust: &'a crate::UpdateTrustRootV2,
    policy: &'a DaemonEnrollmentPolicy<'a>,
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
trait DaemonIdentityVerifier {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool;
}

impl VerifiedDaemonNativeEnrollmentPrepare {
    /// Verifies the current daemon, its installed release, and exact prepare claims.
    #[must_use]
    pub fn verify_current(
        profile_directory: &Path,
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
    ) -> Option<Self> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let policy = compiled_policy()?;
            let paths = NativeEnrollmentArtifactPathsV1::resolve_installed_from_current_daemon().ok()?;
            let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
            verify_with(
                &DaemonVerificationInput {
                    profile_directory,
                    paths: &paths,
                    trust: &trust,
                    policy: &policy,
                    release_tuple_digest,
                    qualification_binding_digest,
                },
                &CurrentDaemonIdentity,
                || {},
            )
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            let _ = (profile_directory, release_tuple_digest, qualification_binding_digest);
            None
        }
    }
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
fn verify_with<I, F>(
    input: &DaemonVerificationInput<'_>,
    identity: &I,
    between_phases: F,
) -> Option<VerifiedDaemonNativeEnrollmentPrepare>
where
    I: DaemonIdentityVerifier,
    F: FnOnce(),
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
        ))
    .then_some(VerifiedDaemonNativeEnrollmentPrepare { _private: () })
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
fn verified_admission(
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
struct CurrentDaemonIdentity;

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
fn compiled_policy() -> Option<DaemonEnrollmentPolicy<'static>> {
    Some(DaemonEnrollmentPolicy {
        profile_id: option_env!("RUNNE_UPDATE_PROFILE_ID").filter(|value| !value.is_empty())?,
        runtime_version: option_env!("RUNNE_UPDATE_RUNTIME_VERSION").filter(|value| !value.is_empty())?,
        channel: option_env!("RUNNE_UPDATE_CHANNEL").filter(|value| !value.is_empty())?,
    })
}

#[cfg(test)]
#[path = "daemon_installed/tests.rs"]
mod tests;
