use runne_secure_store::ProviderCredentialId;

use crate::canonical_provider::readiness::credential_access_policy;

/// Safe credential disposition published by the pre-bootstrap doctor command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialDisposition {
    Configured,
    Missing,
    Unsupported,
    AccessDenied,
    IdentityMismatch,
    Unavailable,
}

impl CredentialDisposition {
    /// Stable non-secret display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
            Self::AccessDenied => "access denied",
            Self::IdentityMismatch => "identity mismatch",
            Self::Unavailable => "unavailable",
        }
    }

    #[must_use]
    pub const fn is_configured(self) -> bool {
        matches!(self, Self::Configured)
    }
}

/// Stable non-secret name of the authoritative credential status source.
#[must_use]
pub const fn credential_source() -> &'static str {
    "runtime credential lifecycle"
}

pub(super) fn credential_disposition(id: ProviderCredentialId) -> CredentialDisposition {
    match credential_access_policy(id) {
        Ok(_) => CredentialDisposition::Missing,
        Err(_) => CredentialDisposition::IdentityMismatch,
    }
}
