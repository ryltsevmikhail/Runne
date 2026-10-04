/// Stable, immutable provider profile choice carried by one TaskRun submit.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectedProviderProfile {
    profile_id: String,
    profile_digest: [u8; 32],
}

impl std::fmt::Debug for SelectedProviderProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedProviderProfile")
            .field("profile_id", &self.profile_id)
            .field("profile_digest", &"[redacted]")
            .finish()
    }
}

impl SelectedProviderProfile {
    /// Creates a bounded profile identity with a nonzero pinned content digest.
    pub fn new(
        profile_id: String,
        profile_digest: [u8; 32],
    ) -> Result<Self, SelectedProviderProfileError> {
        if profile_id.is_empty()
            || profile_id.len() > 256
            || !profile_id.bytes().all(|byte| byte.is_ascii_graphic())
            || profile_digest.iter().all(|byte| *byte == 0)
        {
            return Err(SelectedProviderProfileError);
        }
        Ok(Self {
            profile_id,
            profile_digest,
        })
    }

    /// Returns the exact selected profile identifier.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the immutable profile content digest.
    pub fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }
}

/// Invalid or unbounded provider profile identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedProviderProfileError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_identity_rejects_empty_oversized_and_zero_digest_values() {
        assert!(SelectedProviderProfile::new(String::new(), [1; 32]).is_err());
        assert!(SelectedProviderProfile::new("a".repeat(257), [1; 32]).is_err());
        assert!(SelectedProviderProfile::new("profile/a".into(), [0; 32]).is_err());
        assert!(SelectedProviderProfile::new("profile/a".into(), [1; 32]).is_ok());
    }
}
