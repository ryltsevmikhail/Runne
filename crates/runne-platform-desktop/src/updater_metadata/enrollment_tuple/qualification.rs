use runne_api::{SignedInstalledReleaseCandidateV2, SignedInstalledReleaseCandidateV3};

/// Qualification state produced only from verified metadata and measured bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentQualification {
    Unqualified,
    Qualified(NativeEnrollmentQualificationBinding),
}

/// Opaque non-serializable binding retained for later exact composition checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEnrollmentQualificationBinding {
    release_tuple_sha256: [u8; 32],
    qualification_binding_sha256: [u8; 32],
    expires_at_unix_seconds: u64,
}

impl NativeEnrollmentQualification {
    pub(super) fn from_candidate(
        candidate: Option<&SignedInstalledReleaseCandidateV2>,
        installed_matches: bool,
    ) -> Self {
        candidate
            .filter(|_| installed_matches)
            .map_or(Self::Unqualified, |candidate| {
                Self::Qualified(NativeEnrollmentQualificationBinding {
                    release_tuple_sha256: candidate.release_binding_digest(),
                    qualification_binding_sha256: candidate.qualification_binding_digest(),
                    expires_at_unix_seconds: candidate.expires_at_unix_seconds(),
                })
            })
    }

    pub(super) fn from_candidate_v3(
        candidate: Option<&SignedInstalledReleaseCandidateV3>,
        installed_matches: bool,
    ) -> Self {
        candidate
            .filter(|_| installed_matches)
            .map_or(Self::Unqualified, |candidate| {
                Self::Qualified(NativeEnrollmentQualificationBinding {
                    release_tuple_sha256: candidate.release_binding_digest(),
                    qualification_binding_sha256: candidate.qualification_binding_digest(),
                    expires_at_unix_seconds: candidate.expires_at_unix_seconds(),
                })
            })
    }

    #[must_use]
    pub(crate) const fn retained_qualification_binding_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::Unqualified => None,
            Self::Qualified(binding) => Some(binding.qualification_binding_sha256),
        }
    }

    #[must_use]
    pub fn matches_exact(
        &self,
        release_tuple_sha256: [u8; 32],
        qualification_binding_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> bool {
        match self {
            Self::Unqualified => false,
            Self::Qualified(binding) => {
                binding.release_tuple_sha256 == release_tuple_sha256
                    && binding.qualification_binding_sha256 == qualification_binding_sha256
                    && now_unix_seconds < binding.expires_at_unix_seconds
            }
        }
    }
}

/// ```compile_fail
/// use runne_platform_desktop::{
///     NativeEnrollmentQualification, NativeEnrollmentQualificationBinding,
/// };
///
/// let binding = NativeEnrollmentQualificationBinding {
///     release_tuple_sha256: [0; 32],
///     qualification_binding_sha256: [0; 32],
///     expires_at_unix_seconds: 1,
/// };
/// let _ = NativeEnrollmentQualification::Qualified(binding);
/// ```
const _: () = ();
