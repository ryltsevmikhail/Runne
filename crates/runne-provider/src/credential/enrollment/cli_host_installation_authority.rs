use super::CredentialEnrollmentMeasurementAuthority;
use crate::{
    CredentialBindingDigest, CredentialCliHostInstallationBinding, CredentialEnrollmentError,
};
use sha2::{Digest, Sha256};

impl CredentialEnrollmentMeasurementAuthority {
    /// Seals the measured explicit CLI installation policy in a separate
    /// domain. This is owner-session admission, not release qualification.
    pub fn cli_host_installation_binding(
        &self,
        manifest: [u8; 32],
    ) -> Result<CredentialCliHostInstallationBinding, CredentialEnrollmentError> {
        if manifest == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let mut hash = Sha256::new();
        hash.update(b"runne/linux-cli-credential-host/installation/v1\0");
        hash.update(manifest);
        Ok(CredentialCliHostInstallationBinding::issue(
            CredentialBindingDigest::from_measured(hash.finalize().into())?,
            self.seal.clone(),
        ))
    }
}
