use super::super::{CredentialMaterial, CredentialMutationGrant};
use super::{CredentialRuntimeMutationAdmission, CredentialRuntimeMutationBinding};
use crate::credential::enrollment::CredentialEnrollmentError;

/// Client writer request created only from authenticated one-use handoff.
pub struct CredentialWriterConsumeRequest {
    binding: CredentialRuntimeMutationBinding,
    grant: CredentialMutationGrant,
    material: CredentialMaterial,
}

/// Service-ingress writer value; it does not claim client authorization.
pub struct CredentialWriterIngressRequest(CredentialWriterConsumeRequest);

impl CredentialWriterConsumeRequest {
    pub(crate) fn from_authenticated_parts(
        binding: CredentialRuntimeMutationBinding,
        grant: CredentialMutationGrant,
        material: CredentialMaterial,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !binding.grant_digest.ct_matches(grant.digest()) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(Self {
            binding,
            grant,
            material,
        })
    }
    pub(crate) const fn binding(&self) -> &CredentialRuntimeMutationBinding {
        &self.binding
    }
    pub(crate) const fn grant(&self) -> &CredentialMutationGrant {
        &self.grant
    }
    pub(crate) const fn material(&self) -> &CredentialMaterial {
        &self.material
    }
}

impl CredentialWriterIngressRequest {
    pub(crate) const fn binding(&self) -> &CredentialRuntimeMutationBinding {
        &self.0.binding
    }

    /// Returns the installation owner carried by the exact writer binding.
    pub const fn installation_owner(&self) -> [u8; 32] {
        self.0.binding.installation_owner
    }

    pub(crate) fn from_wire(
        binding: CredentialRuntimeMutationBinding,
        grant: CredentialMutationGrant,
        material: CredentialMaterial,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !binding.grant_digest.ct_matches(grant.digest()) {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(Self(CredentialWriterConsumeRequest {
            binding,
            grant,
            material,
        }))
    }

    /// Moves decoded one-use values into service admission core.
    pub fn into_parts(
        self,
    ) -> (
        CredentialRuntimeMutationAdmission,
        CredentialMutationGrant,
        CredentialMaterial,
    ) {
        (
            CredentialRuntimeMutationAdmission(self.0.binding),
            self.0.grant,
            self.0.material,
        )
    }
}
