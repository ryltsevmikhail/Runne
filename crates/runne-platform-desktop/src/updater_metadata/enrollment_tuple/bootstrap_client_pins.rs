//! Installed, signed transport expectations; never runtime qualification.

use runne_api::RunBinding;

use super::{NativeEnrollmentQualification, NativeEnrollmentTupleAdmission, VerifiedUpdateV2};

/// Pinned bootstrap transport admitted only after measuring the installed package.
///
/// This value cannot grant provider credentials or ordinary runtime capabilities.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedQualificationBootstrapClientPins;
/// let _ = VerifiedQualificationBootstrapClientPins {};
/// ```
/// ```compile_fail
/// use runne_platform_desktop::VerifiedQualificationBootstrapClientPins;
/// fn clone_required<T: Clone>() {}
/// clone_required::<VerifiedQualificationBootstrapClientPins>();
/// ```
/// ```compile_fail
/// use runne_platform_desktop::VerifiedQualificationBootstrapClientPins;
/// fn wire_required<T: serde::Serialize>() {}
/// wire_required::<VerifiedQualificationBootstrapClientPins>();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedQualificationBootstrapClientPins {
    descriptor: runne_api::QualificationBootstrapClientV1,
    candidate: [u8; 32],
    raw_tuple: [u8; 32],
    manifest: [u8; 32],
    generation: u64,
    expires_at: u64,
}

impl VerifiedQualificationBootstrapClientPins {
    /// Checks the root-prepared binding against all independently admitted hashes.
    #[must_use]
    pub fn matches_prepared_binding(&self, binding: &RunBinding) -> bool {
        self.current()
            && binding.candidate_sha256() == self.candidate
            && binding.raw_v3_tuple_sha256() == self.raw_tuple
            && binding.manifest_sha256() == self.manifest
            && binding.profile_sha256() == self.descriptor.qualification_profile_sha256()
    }

    fn current(&self) -> bool {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|now| now.as_secs() < self.expires_at)
    }
}

// Called only after the path adapter measures the installed V3 and confirms paths.
// Public admission from caller-provided tuple bytes deliberately cannot mint pins.
pub(super) fn mint_after_installed_measurement(
    verified: &VerifiedUpdateV2,
    admission: &NativeEnrollmentTupleAdmission,
) -> Option<VerifiedQualificationBootstrapClientPins> {
    if !matches!(
        admission.qualification(),
        NativeEnrollmentQualification::Unqualified
    ) {
        return None;
    }
    let tuple = verified.native_enrollment_tuple_v3()?;
    if admission.raw_v3_tuple_sha256 != Some(tuple.tuple_digest())
        || admission.raw_v3_candidate_sha256 != Some(tuple.candidate_digest())
        || admission.installed_generation != verified.metadata().targets.version
    {
        return None;
    }
    let metadata = verified.metadata();
    Some(VerifiedQualificationBootstrapClientPins {
        descriptor: verified
            .target()
            .qualification_bootstrap_client_v1
            .as_ref()?
            .clone(),
        candidate: tuple.candidate_digest(),
        raw_tuple: tuple.tuple_digest(),
        manifest: verified.signed.target_manifest_digest(),
        generation: admission.installed_generation,
        expires_at: [
            metadata.targets.target.expires_at_unix_seconds,
            metadata.targets.expires_at_unix_seconds,
            metadata.snapshot.expires_at_unix_seconds,
            metadata.timestamp.expires_at_unix_seconds,
        ]
        .into_iter()
        .min()?,
    })
}

#[cfg(target_os = "macos")]
#[path = "bootstrap_client_pins/transport.rs"]
mod transport;

#[cfg(test)]
#[path = "bootstrap_client_pins/tests.rs"]
mod tests;
