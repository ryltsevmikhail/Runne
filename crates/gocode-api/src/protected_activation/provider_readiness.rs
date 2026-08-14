
/// Metadata-only provider readiness disposition.
///
/// No credential bytes, keychain errors, or paths enter this type.
/// It is bound into the authenticated V2 ready payload so Desktop
/// can map each variant to an exact lifecycle failure code without
/// importing `gocode-secure-store`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderActivationReadinessV1 {
    /// Provider credential, ACL, journal key and secure-store backend
    /// are all exactly configured.
    Ready,
    /// Credential metadata is not configured.
    CredentialMissing,
    /// Native credential access policy denied the reader.
    CredentialAccessDenied,
    /// Credential identity (executable path/hash) does not match the
    /// expected writer/reader pair.
    CredentialIdentityMismatch,
    /// Secure-store backend is unavailable or unsupported on this
    /// platform.
    SecureStoreUnavailable,
}

impl ProviderActivationReadinessV1 {
    /// Returns the exact bounded unsigned wire code.
    pub(crate) fn wire_code(self) -> u64 {
        match self {
            Self::Ready => 0,
            Self::CredentialMissing => 1,
            Self::CredentialAccessDenied => 2,
            Self::CredentialIdentityMismatch => 3,
            Self::SecureStoreUnavailable => 4,
        }
    }

    /// Decodes one exact wire code or returns `None` for unknown variants.
    pub(crate) fn from_wire_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Ready),
            1 => Some(Self::CredentialMissing),
            2 => Some(Self::CredentialAccessDenied),
            3 => Some(Self::CredentialIdentityMismatch),
            4 => Some(Self::SecureStoreUnavailable),
            _ => None,
        }
    }

    /// Returns `true` only for the exact `Ready` disposition.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}
