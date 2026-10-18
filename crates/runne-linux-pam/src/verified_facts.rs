/// Move-only facts extracted from a consumed, validated PAM reauthentication.
///
/// This type has private fields and no public constructor, serializer, or
/// cloning/debug implementation. Values can only be obtained by consuming a
/// [`crate::FreshOsReauthentication`] token after its challenge, UID, policy
/// fingerprint, and monotonic lifetime have been checked.
///
/// ```compile_fail
/// let _ = runne_linux_pam::VerifiedPamFacts::new();
/// ```
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_linux_pam::VerifiedPamFacts>();
/// ```
///
/// ```compile_fail
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<runne_linux_pam::VerifiedPamFacts>();
/// ```
#[must_use]
pub struct VerifiedPamFacts {
    challenge_digest: [u8; 32],
    uid: u32,
    qualified_fingerprint: [u8; 32],
    authenticated_at_unix_ms: u64,
}

impl VerifiedPamFacts {
    pub(crate) const fn from_consumed_token(
        challenge_digest: [u8; 32],
        uid: u32,
        qualified_fingerprint: [u8; 32],
        authenticated_at_unix_ms: u64,
    ) -> Self {
        Self {
            challenge_digest,
            uid,
            qualified_fingerprint,
            authenticated_at_unix_ms,
        }
    }

    /// Returns the challenge digest bound to the consumed PAM token.
    #[must_use]
    pub const fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    /// Returns the operating-system UID authenticated by PAM.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the qualified host-policy fingerprint bound to PAM.
    #[must_use]
    pub const fn qualified_fingerprint(&self) -> [u8; 32] {
        self.qualified_fingerprint
    }

    /// Returns the worker-captured successful authentication time in Unix milliseconds.
    #[must_use]
    pub const fn authenticated_at_unix_ms(&self) -> u64 {
        self.authenticated_at_unix_ms
    }
}
