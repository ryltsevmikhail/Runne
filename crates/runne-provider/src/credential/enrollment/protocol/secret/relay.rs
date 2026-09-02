use zeroize::Zeroizing;

/// Temporary plaintext held only while the paired native writer callback runs.
pub(crate) struct CredentialDecryptedMaterial {
    material: Zeroizing<Vec<u8>>,
}

impl CredentialDecryptedMaterial {
    pub(crate) const fn new(material: Zeroizing<Vec<u8>>) -> Self {
        Self { material }
    }

    pub(crate) fn consume<E>(self, callback: impl FnOnce(&[u8]) -> Result<(), E>) -> Result<(), E> {
        callback(&self.material)
    }

    pub(crate) fn into_service_material(
        self,
    ) -> Result<crate::CredentialMaterial, crate::CredentialEnrollmentError> {
        crate::CredentialMaterial::from_zeroizing(self.material)
    }
}

impl core::fmt::Debug for CredentialDecryptedMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CredentialDecryptedMaterial(<redacted>)")
    }
}
