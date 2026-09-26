use super::super::{
    DaemonEnrollmentPolicy, NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission,
    refresh_retained_admission_at, verified_admission,
};
use crate::UpdateTrustRootV2;
use std::path::Path;

/// Verifies signed journals rooted inside the canonical bundled runtime.
pub(super) fn verified_linux_admission(
    profile: &Path,
    runtime: &Path,
    paths: &NativeEnrollmentArtifactPathsV1,
    trust: &UpdateTrustRootV2,
    policy: &DaemonEnrollmentPolicy<'_>,
) -> Option<NativeEnrollmentTupleAdmission> {
    super::valid_profile_runtime_pair(profile, runtime).then_some(())?;
    verified_admission(runtime, paths, trust, policy)
}

/// Refreshes the exact retained admission from journals in the bundled runtime.
pub(super) fn refresh_linux_admission(
    profile: &Path,
    runtime: &Path,
    paths: &NativeEnrollmentArtifactPathsV1,
    trust: &UpdateTrustRootV2,
    policy: &DaemonEnrollmentPolicy<'_>,
    retained: &NativeEnrollmentTupleAdmission,
    now: u64,
) -> Option<NativeEnrollmentTupleAdmission> {
    super::valid_profile_runtime_pair(profile, runtime).then_some(())?;
    refresh_retained_admission_at(runtime, paths, trust, policy, retained, now)
}
