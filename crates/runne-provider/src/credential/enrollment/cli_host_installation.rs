//! Explicit standalone owner-session installation binding. It grants no
//! signed release qualification and cannot be used as a Desktop launch proof.
use super::{
    CredentialBindingDigest, CredentialQualifiedReleaseTuple, authority::EnrollmentAuthoritySeal,
};
use std::sync::Arc;

/// Owner-session installation binding, deliberately separate from release qualification.
#[derive(Debug)]
pub struct CredentialCliHostInstallationBinding {
    digest: CredentialBindingDigest,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl CredentialCliHostInstallationBinding {
    pub(super) fn issue(
        digest: CredentialBindingDigest,
        seal: Arc<EnrollmentAuthoritySeal>,
    ) -> Self {
        Self { digest, seal }
    }
    /// Returns the domain-separated non-secret installation binding.
    pub const fn digest(&self) -> CredentialBindingDigest {
        self.digest
    }
    pub(super) fn into_storage_binding(self) -> CredentialQualifiedReleaseTuple {
        // The historical column name is shared with Desktop enrollment. The
        // CLI domain separation does not assert signed-package qualification.
        CredentialQualifiedReleaseTuple::issue(self.seal, self.digest)
    }
}

#[cfg(test)]
mod tests {
    use crate::CredentialEnrollmentAuthorityPair;
    #[test]
    fn cli_installation_is_sealed_and_domain_separated_from_release_digest() {
        let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let binding = measurements.cli_host_installation_binding([7; 32]).unwrap();
        assert_ne!(binding.digest().as_bytes(), [7; 32]);
    }
    #[test]
    fn absent_manifest_cannot_admit_a_cli_host() {
        let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        assert!(measurements.cli_host_installation_binding([0; 32]).is_err());
    }
}
