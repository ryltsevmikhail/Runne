use sha2::{Digest, Sha256};

use super::super::{CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationAction};
use super::{CredentialBrokerCommand, CredentialBrokerTarget};

impl CredentialBrokerCommand {
    /// Computes the persisted import observation binding for one exact source revision.
    ///
    /// This is non-secret evidence, not permission to read or delete a source.
    /// Ticket attempts are intentionally excluded from this durable observation.
    ///
    /// # Errors
    ///
    /// Rejects a zero revision or a command that is not an exact legacy import.
    pub fn legacy_source_observation_digest(
        &self,
        source_revision: [u8; 16],
    ) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
        let CredentialBrokerTarget::LegacyImport(reference) = self.target() else {
            return Err(CredentialEnrollmentError::InvalidInput);
        };
        if self.action() != CredentialOperationAction::MigrateLegacy || source_revision == [0; 16] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        let mut digest = Sha256::new();
        digest.update(b"runne/provider-credential-readback/v1\0");
        digest.update(self.operation_id().as_bytes());
        digest.update(self.provider().as_str().as_bytes());
        digest.update([self.action() as u8, 1]);
        digest.update(self.expected_lifecycle_revision().get().to_be_bytes());
        digest.update(self.expected_prior_fence().get().to_be_bytes());
        digest.update([3]); // Existing LEGACY_IMPORT_TARGET transcript tag.
        digest.update(reference.provider().as_str().as_bytes());
        digest.update(reference.version().to_be_bytes());
        digest.update(reference.ref_digest());
        digest.update(source_revision);
        CredentialBindingDigest::from_measured(digest.finalize().into())
    }
}
