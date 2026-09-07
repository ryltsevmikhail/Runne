use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{UpdateTargetV2, VerifiedSignedInstalledReleaseV2};

const MAX_CANDIDATE_BINDING_BYTES: usize = 65_536;

#[derive(Eq, PartialEq)]
pub(super) struct VerifiedCandidateBindingV3 {
    arch: String,
    platform: String,
    product_id: String,
    profile_id: String,
    release_candidate_sha256: String,
    version: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateBindingV3 {
    arch: String,
    platform: String,
    product_id: String,
    profile_id: String,
    release_candidate_sha256: String,
    schema_version: u32,
    version: String,
}

impl VerifiedCandidateBindingV3 {
    pub(super) fn from_target(target: &UpdateTargetV2) -> Self {
        Self {
            arch: target.arch.clone(),
            platform: target.platform.clone(),
            product_id: target.product_id.clone(),
            profile_id: target.profile_id.clone(),
            release_candidate_sha256: target.release_candidate_sha256.clone(),
            version: target.version.clone(),
        }
    }

    fn matches(&self, candidate: &CandidateBindingV3) -> bool {
        self.arch == candidate.arch
            && self.platform == candidate.platform
            && self.product_id == candidate.product_id
            && self.profile_id == candidate.profile_id
            && self.release_candidate_sha256 == candidate.release_candidate_sha256
            && self.version == candidate.version
    }
}

impl VerifiedSignedInstalledReleaseV2 {
    #[doc(hidden)]
    pub fn matches_native_enrollment_v3_candidate_binding(&self, canonical_binding: &[u8]) -> bool {
        if canonical_binding.len() > MAX_CANDIDATE_BINDING_BYTES {
            return false;
        }
        let Ok(candidate) = serde_json::from_slice::<CandidateBindingV3>(canonical_binding) else {
            return false;
        };
        if !serde_json::to_vec(&candidate).is_ok_and(|encoded| encoded == canonical_binding) {
            return false;
        }
        let Some(expected) = self.candidate_binding_v3.as_ref() else {
            return false;
        };
        if candidate.schema_version != 1 || !expected.matches(&candidate) {
            return false;
        }
        let Some(tuple) = self.native_enrollment_tuple_v3() else {
            return false;
        };
        let mut embedded_digest = [0_u8; 32];
        hex::decode_to_slice(&candidate.release_candidate_sha256, &mut embedded_digest).is_ok()
            && bool::from(tuple.candidate_digest().ct_eq(&embedded_digest))
    }
}
