use super::CredentialMaterial;
use crate::CredentialEnrollmentError;

/// One atomically observed legacy secret and its nonzero source revision.
/// This value carries source facts, not claim or native-access authority.
pub struct CredentialLegacySourceMaterial {
    material: CredentialMaterial,
    source_revision: [u8; 16],
}

impl CredentialLegacySourceMaterial {
    /// Keeps the zeroizing secret coupled to its observed source revision.
    pub fn new(
        material: CredentialMaterial,
        source_revision: [u8; 16],
    ) -> Result<Self, CredentialEnrollmentError> {
        if source_revision == [0; 16] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            material,
            source_revision,
        })
    }

    /// Non-secret exact source revision, retained for destination readback.
    #[must_use]
    pub const fn source_revision(&self) -> [u8; 16] {
        self.source_revision
    }

    /// Moves both source facts into the authenticated service request.
    #[must_use]
    pub fn into_parts(self) -> (CredentialMaterial, [u8; 16]) {
        (self.material, self.source_revision)
    }
}
