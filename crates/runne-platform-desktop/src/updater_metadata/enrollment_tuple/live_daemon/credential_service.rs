use crate::ProtectedBundledRuntimeError;

use super::ConfirmedInstalledNativeEnrollment;

impl ConfirmedInstalledNativeEnrollment {
    pub(crate) fn desktop_credential_service_configuration(
        &self,
    ) -> Result<runne_macos_xpc::CredentialServiceEndpointConfiguration, ProtectedBundledRuntimeError>
    {
        self.admission
            .desktop_credential_service_configuration()
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
    }

    pub(crate) const fn release_binding(&self) -> [u8; 32] {
        self.evidence.release_tuple
    }
}
