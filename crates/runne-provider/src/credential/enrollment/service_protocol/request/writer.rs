use super::super::{CredentialMaterial, CredentialMutationGrant};
use super::{CredentialRuntimeMutationAdmission, CredentialRuntimeMutationBinding};
use crate::credential::enrollment::{CredentialEnrollmentError, CredentialOperationAction};

/// Client writer request created only from authenticated one-use handoff.
pub struct CredentialWriterConsumeRequest {
    binding: CredentialRuntimeMutationBinding,
    grant: CredentialMutationGrant,
    material: Option<CredentialMaterial>,
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
        let request = Self {
            binding,
            grant,
            material: Some(material),
        };
        request.validate_material()?;
        Ok(request)
    }
    pub(crate) fn from_authenticated_control_parts(
        binding: CredentialRuntimeMutationBinding,
        grant: CredentialMutationGrant,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !binding.grant_digest.ct_matches(grant.digest()) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let request = Self {
            binding,
            grant,
            material: None,
        };
        request.validate_material()?;
        Ok(request)
    }
    pub(crate) const fn binding(&self) -> &CredentialRuntimeMutationBinding {
        &self.binding
    }
    pub(crate) const fn grant(&self) -> &CredentialMutationGrant {
        &self.grant
    }
    pub(crate) fn material_bytes(&self) -> &[u8] {
        self.material
            .as_ref()
            .map_or(&[], CredentialMaterial::wire_bytes)
    }
    fn validate_material(&self) -> Result<(), CredentialEnrollmentError> {
        let valid = match self.binding.command.action() {
            CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
                self.material.is_some()
            }
            CredentialOperationAction::Revoke
            | CredentialOperationAction::RetiredVersionCleanup => self.material.is_none(),
            CredentialOperationAction::LegacySourceCleanup
            | CredentialOperationAction::WriterIdentityMigrationEffect
            | CredentialOperationAction::WriterIdentityMigrationVerify => false,
        };
        valid
            .then_some(())
            .ok_or(CredentialEnrollmentError::InvalidInput)
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
        material: Option<CredentialMaterial>,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !binding.grant_digest.ct_matches(grant.digest()) {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let request = CredentialWriterConsumeRequest {
            binding,
            grant,
            material,
        };
        request
            .validate_material()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        Ok(Self(request))
    }

    /// Moves decoded one-use values into service admission core.
    pub fn into_parts(
        self,
    ) -> (
        CredentialRuntimeMutationAdmission,
        CredentialMutationGrant,
        Option<CredentialMaterial>,
    ) {
        (
            CredentialRuntimeMutationAdmission(self.0.binding),
            self.0.grant,
            self.0.material,
        )
    }
}
