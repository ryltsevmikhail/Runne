
pub(super) struct DaemonEnrollmentPolicy<'a> {
    pub(super) profile_id: &'a str,
    pub(super) runtime_version: &'a str,
    pub(super) channel: &'a str,
}

pub(super) struct DaemonVerificationInput<'a> {
    pub(super) profile_directory: &'a Path,
    pub(super) paths: &'a NativeEnrollmentArtifactPathsV1,
    pub(super) trust: &'a crate::UpdateTrustRootV2,
    pub(super) policy: &'a DaemonEnrollmentPolicy<'a>,
    pub(super) release_tuple_digest: [u8; 32],
    pub(super) qualification_binding_digest: [u8; 32],
}

pub(super) trait DaemonIdentityVerifier {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool;
}

#[cfg(test)]
pub(super) fn verify_with<I, F>(
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
    let _ = verified_admission(
        input.profile_directory,
        input.paths,
        input.trust,
        input.policy,
    )?;
    between_phases();
    let admission = verified_admission(
        input.profile_directory,
        input.paths,
        input.trust,
        input.policy,
    )?;
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
        )
        && final_check(&admission))
    .then_some(admission)
}

pub(super) fn verified_admission(
    profile_directory: &Path,
    paths: &NativeEnrollmentArtifactPathsV1,
    trust: &crate::UpdateTrustRootV2,
    policy: &DaemonEnrollmentPolicy<'_>,
) -> Option<NativeEnrollmentTupleAdmission> {
    verified_admission_at(
        profile_directory,
        paths,
        trust,
        policy,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs(),
    )
}

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

fn verified_admission_at(
    profile_directory: &Path,
    paths: &NativeEnrollmentArtifactPathsV1,
    trust: &crate::UpdateTrustRootV2,
    policy: &DaemonEnrollmentPolicy<'_>,
    now: u64,
) -> Option<NativeEnrollmentTupleAdmission> {
    use crate::updater_installed_metadata::InstalledUpdateMetadataJournal;
    use crate::{
        UpdateInstallState, UpdateJournal, UpdateTargetV2Binding, UpdateTrustJournal,
        verify_update_v2,
    };
    let artifacts = paths.measure().ok()?;
    let (runtime_digest, bundle_sha256) = artifacts.daemon_and_contract_digests();
    let updates = profile_directory.join("updates");
    let record = UpdateJournal::new(updates.join("install-state.json"))
        .read()
        .ok()??;
    let trust_state = UpdateTrustJournal::new(updates.join("trust-state.json"))
        .read()
        .ok()??;
    let (metadata, metadata_binding) =
        InstalledUpdateMetadataJournal::new(updates.join("installed-metadata.json"))
            .read()
            .ok()??;
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
    let admission = (verified.target().version == record.version
        && verified.target().artifact_sha256 == record.artifact_sha256)
        .then(|| paths.admit_verified(&verified).ok().flatten())??;
    #[cfg(all(feature = "test-support", target_os = "macos"))]
    if runne_api::test_support::local_native_enrollment_enabled() {
        return admission.with_local_code_identities(paths);
    }
    Some(admission)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn compiled_policy() -> Option<DaemonEnrollmentPolicy<'static>> {
    let compiled = || {
        Some(DaemonEnrollmentPolicy {
            profile_id: option_env!("RUNNE_UPDATE_PROFILE_ID").filter(|value| !value.is_empty())?,
            runtime_version: option_env!("RUNNE_UPDATE_RUNTIME_VERSION")
                .filter(|value| !value.is_empty())?,
            channel: option_env!("RUNNE_UPDATE_CHANNEL").filter(|value| !value.is_empty())?,
        })
    };
    compiled().or_else(local_test_policy)
}

#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
fn local_test_policy() -> Option<DaemonEnrollmentPolicy<'static>> {
    runne_api::test_support::local_native_enrollment_enabled().then_some(DaemonEnrollmentPolicy {
        profile_id: "slice-e-local",
        runtime_version: "0.1.0",
        channel: "local",
    })
}

#[cfg(all(
    not(feature = "test-support"),
    target_os = "macos",
    target_arch = "aarch64"
))]
const fn local_test_policy() -> Option<DaemonEnrollmentPolicy<'static>> {
    None
}
