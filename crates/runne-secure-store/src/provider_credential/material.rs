/// Maximum legacy credential material retained by V1 APIs and codecs.
pub const MAX_PROVIDER_CREDENTIAL_BYTES: usize = 4_096;

/// Maximum serialized native OAuth envelope size.
pub const MAX_NATIVE_OAUTH_CREDENTIAL_BYTES: usize = 32 * 1024;

/// Storage format selected by an admitted credential protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialMaterialKind {
    /// Legacy API key or opaque provider credential.
    Legacy,
    /// Versioned OAuth envelope whose complete JSON is retained.
    NativeOAuth,
}

/// Zeroizing, bounded provider credential material.
pub struct ProviderCredentialMaterial {
    bytes: Zeroizing<Vec<u8>>,
    kind: ProviderCredentialMaterialKind,
}

impl ProviderCredentialMaterial {
    /// Validates and takes ownership of one non-empty, single-line legacy secret.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or control-byte-containing input.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecureStoreError> {
        Self::new_inner(bytes, ProviderCredentialMaterialKind::Legacy)
    }

    /// Validates and takes ownership of an already-zeroizing legacy allocation.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or control-byte-containing input.
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Result<Self, SecureStoreError> {
        Self::new_zeroizing(bytes, ProviderCredentialMaterialKind::Legacy)
    }

    /// Validates one complete native OAuth envelope under its larger typed bound.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or control-byte-containing input.
    pub fn new_native_oauth(bytes: Vec<u8>) -> Result<Self, SecureStoreError> {
        Self::new_inner(bytes, ProviderCredentialMaterialKind::NativeOAuth)
    }

    fn new_inner(
        bytes: Vec<u8>,
        kind: ProviderCredentialMaterialKind,
    ) -> Result<Self, SecureStoreError> {
        Self::new_zeroizing(Zeroizing::new(bytes), kind)
    }

    fn new_zeroizing(
        bytes: Zeroizing<Vec<u8>>,
        kind: ProviderCredentialMaterialKind,
    ) -> Result<Self, SecureStoreError> {
        let max = match kind {
            ProviderCredentialMaterialKind::Legacy => MAX_PROVIDER_CREDENTIAL_BYTES,
            ProviderCredentialMaterialKind::NativeOAuth => MAX_NATIVE_OAUTH_CREDENTIAL_BYTES,
        };
        if bytes.is_empty()
            || bytes.len() > max
            || bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(SecureStoreError::InvalidProviderCredential);
        }
        Ok(Self { bytes, kind })
    }

    /// Returns the typed storage format.
    #[must_use]
    pub const fn kind(&self) -> ProviderCredentialMaterialKind {
        self.kind
    }

    /// Borrows credential bytes only for the duration of `operation`.
    pub fn with_bytes<T>(&self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(&self.bytes)
    }

    /// Moves the zeroizing allocation and its storage kind to the next owner.
    #[must_use]
    pub fn into_zeroizing(self) -> (ProviderCredentialMaterialKind, Zeroizing<Vec<u8>>) {
        (self.kind, self.bytes)
    }

    #[cfg(feature = "provider-credential-broker-writer")]
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl fmt::Debug for ProviderCredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentialMaterial")
            .field("bytes", &"<redacted>")
            .field("kind", &self.kind)
            .finish()
    }
}
