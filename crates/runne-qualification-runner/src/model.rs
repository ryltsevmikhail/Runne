use std::fmt;

/// Immutable policy hashes for a qualified source/run/namespace tuple.
pub struct CanonicalRunBinding {
    manifest_sha256: [u8; 32],
    profile_sha256: [u8; 32],
}

impl CanonicalRunBinding {
    /// Creates the policy portion of the immutable run binding.
    ///
    /// # Errors
    ///
    /// Rejects absent manifest or qualification-profile identities.
    pub fn new(
        manifest_sha256: [u8; 32],
        profile_sha256: [u8; 32],
    ) -> Result<Self, CanonicalRunBindingError> {
        if manifest_sha256 == [0; 32] || profile_sha256 == [0; 32] {
            return Err(CanonicalRunBindingError);
        }
        Ok(Self {
            manifest_sha256,
            profile_sha256,
        })
    }

    pub(crate) const fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    pub(crate) const fn profile_sha256(&self) -> [u8; 32] {
        self.profile_sha256
    }
}

/// Closed rejection for an incomplete policy binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalRunBindingError;

impl fmt::Display for CanonicalRunBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification run binding rejected")
    }
}

impl std::error::Error for CanonicalRunBindingError {}
