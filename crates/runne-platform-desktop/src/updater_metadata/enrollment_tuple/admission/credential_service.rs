use runne_macos_xpc::{
    CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
    CredentialServicePeerRequirement, CredentialServiceXpcError,
};

use super::{NativeEnrollmentQualification, NativeEnrollmentTupleAdmission};

impl NativeEnrollmentTupleAdmission {
    pub(crate) fn desktop_credential_service_configuration(
        &self,
    ) -> Result<CredentialServiceEndpointConfiguration, CredentialServiceXpcError> {
        self.credential_service_configuration(
            CredentialServiceEndpointRole::Desktop,
            self.macos_desktop_code_identity.as_ref(),
        )
    }

    pub(crate) fn runtime_credential_service_configuration(
        &self,
    ) -> Result<CredentialServiceEndpointConfiguration, CredentialServiceXpcError> {
        self.credential_service_configuration(
            CredentialServiceEndpointRole::Runtime,
            self.macos_daemon_code_identity.as_ref(),
        )
    }

    pub(crate) fn writer_credential_service_configuration(
        &self,
    ) -> Result<CredentialServiceEndpointConfiguration, CredentialServiceXpcError> {
        self.credential_service_configuration(
            CredentialServiceEndpointRole::Writer,
            self.macos_writer_code_identity.as_ref(),
        )
    }

    fn credential_service_configuration(
        &self,
        role: CredentialServiceEndpointRole,
        client_identity: Option<&crate::updater_metadata::macos_identity::MacOsCodeIdentityV1>,
    ) -> Result<CredentialServiceEndpointConfiguration, CredentialServiceXpcError> {
        if !matches!(
            self.qualification,
            NativeEnrollmentQualification::Qualified(_)
        ) {
            return Err(CredentialServiceXpcError::Rejected);
        }
        self.credential_service_sha256
            .ok_or(CredentialServiceXpcError::Rejected)?;
        let service = requirement(
            self.macos_credential_service_code_identity
                .as_ref()
                .ok_or(CredentialServiceXpcError::Rejected)?,
        )?;
        let client = requirement(client_identity.ok_or(CredentialServiceXpcError::Rejected)?)?;
        CredentialServiceEndpointConfiguration::new(role, role.endpoint_name(), service, client)
    }
}

fn requirement(
    identity: &crate::updater_metadata::macos_identity::MacOsCodeIdentityV1,
) -> Result<CredentialServicePeerRequirement, CredentialServiceXpcError> {
    #[cfg(feature = "test-support")]
    if let Some(requirement) = identity.local_xpc_requirement() {
        return Ok(requirement);
    }
    CredentialServicePeerRequirement::new(identity.requirement())
}
