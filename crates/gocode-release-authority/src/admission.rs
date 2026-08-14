//! Fixture-only staged admission that never accepts future release materials early.

use crate::{AuthorityError, CandidateBinding, CanonicalPayloadKind, InspectedCanonicalPayload};

/// Opaque RC0 ingest input: exactly one strict unsigned manifest bound to the candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureAdmission {
    binding: CandidateBinding,
    unsigned_manifest: InspectedCanonicalPayload,
}

impl FixtureAdmission {
    /// Build the first fixture-only admission step without any RC1/RC2/RC3 or signed material.
    ///
    /// # Errors
    /// Returns an error unless the strict raw manifest binds all five candidate components.
    pub fn ingest(
        binding: CandidateBinding,
        unsigned_manifest: InspectedCanonicalPayload,
    ) -> Result<Self, AuthorityError> {
        if !binding.is_fixture()
            || unsigned_manifest.kind() != CanonicalPayloadKind::UnsignedManifest
            || !unsigned_manifest.matches_binding(&binding)
        {
            return Err(AuthorityError::BindingMismatch);
        }
        Ok(Self {
            binding,
            unsigned_manifest,
        })
    }

    pub(crate) fn matches(&self, binding: &CandidateBinding) -> bool {
        &self.binding == binding
    }
    pub(crate) fn stored_facts(&self) -> crate::admission_facts::StoredAdmissionFacts {
        crate::admission_facts::StoredAdmissionFacts::from_manifest(&self.unsigned_manifest)
    }
}
