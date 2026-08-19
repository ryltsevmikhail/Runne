//! Store-owned trusted snapshot used for final RC2 evidence revalidation.

use crate::{AuthorityError, FixturePrevalidatedSignedBundle};

#[derive(Clone)]
pub struct StoredRc2EvidenceTrust {
    pub(crate) now: u64,
    pub(crate) revocation_epoch: u64,
    pub(crate) generation: u64,
    pub(crate) registrations: Vec<crate::FixtureEvidenceKeyRegistration>,
}

impl Default for StoredRc2EvidenceTrust {
    fn default() -> Self {
        Self {
            now: 1,
            revocation_epoch: 1,
            generation: 1,
            registrations: Vec::new(),
        }
    }
}

impl StoredRc2EvidenceTrust {
    pub(crate) fn snapshot(&self) -> Result<crate::FixtureEvidenceTrustState, AuthorityError> {
        crate::FixtureEvidenceTrustState::try_new(
            self.now,
            self.revocation_epoch,
            self.generation,
            self.registrations.clone(),
        )
    }

    pub(crate) fn revalidates(
        &self,
        bundle: &FixturePrevalidatedSignedBundle,
    ) -> Result<(), AuthorityError> {
        let trust = bundle.evidence_trust();
        (self.snapshot()?.binding() == trust
            && self.now < bundle.evidence_expires_at()
            && self.now >= bundle.authorization_valid_from()
            && self.now < bundle.authorization_expires_at()
            && bundle.authorization_epoch() == self.revocation_epoch)
            .then_some(())
            .ok_or(AuthorityError::BindingMismatch)
    }
}
