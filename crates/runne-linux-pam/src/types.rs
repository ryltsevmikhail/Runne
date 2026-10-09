use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::identity;
use crate::verified_facts::VerifiedPamFacts;

/// Maximum lifetime accepted for a fresh PAM challenge.
pub const MAX_REAUTH_WINDOW: std::time::Duration = std::time::Duration::from_mins(5);

/// Opaque, single-use result of a fresh Linux OS reauthentication.
///
/// It cannot be built, cloned, serialized, or formatted by callers.
///
/// ```compile_fail
/// fn clone_token<T: Clone>() {}
/// clone_token::<runne_linux_pam::FreshOsReauthentication>();
/// ```
///
/// ```compile_fail
/// let _ = runne_linux_pam::FreshOsReauthentication::new();
/// ```
///
/// ```compile_fail
/// fn consume_once(token: runne_linux_pam::FreshOsReauthentication) {
///     let _facts = token.consume_verified([1; 32], [2; 32]);
///     let _again = token.consume([1; 32], [2; 32]);
/// }
/// ```
#[must_use]
pub struct FreshOsReauthentication {
    challenge_digest: [u8; 32],
    uid: u32,
    qualified_fingerprint: [u8; 32],
    authenticated_at_unix_ms: u64,
    deadline: Instant,
    completed_at: Instant,
}

impl FreshOsReauthentication {
    pub(super) const fn verified(
        challenge_digest: [u8; 32],
        uid: u32,
        qualified_fingerprint: [u8; 32],
        authenticated_at_unix_ms: u64,
        deadline: Instant,
        completed_at: Instant,
    ) -> Self {
        Self {
            challenge_digest,
            uid,
            qualified_fingerprint,
            authenticated_at_unix_ms,
            deadline,
            completed_at,
        }
    }

    /// Consumes this token after matching the exact challenge and current policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity or binding differs, or the token expired.
    pub fn consume(
        self,
        challenge_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<(), ReauthenticationError> {
        let current_uid = identity::current_uid()?;
        self.validate_for(challenge_digest, current_uid, policy_digest, Instant::now())?;
        Ok(())
    }

    /// Consumes this token and returns facts captured by the private PAM worker.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity or binding differs, the token expired,
    /// or the current OS identity cannot be read.
    pub fn consume_verified(
        self,
        challenge_digest: [u8; 32],
        qualified_fingerprint: [u8; 32],
    ) -> Result<VerifiedPamFacts, ReauthenticationError> {
        let current_uid = identity::current_uid()?;
        self.facts_for(
            challenge_digest,
            current_uid,
            qualified_fingerprint,
            Instant::now(),
        )
    }

    fn validate_for(
        &self,
        challenge_digest: [u8; 32],
        uid: u32,
        qualified_fingerprint: [u8; 32],
        now: Instant,
    ) -> Result<(), ReauthenticationError> {
        if self.challenge_digest != challenge_digest
            || self.uid != uid
            || self.qualified_fingerprint != qualified_fingerprint
            || self.challenge_digest == [0; 32]
            || self.qualified_fingerprint == [0; 32]
        {
            return Err(ReauthenticationError::TokenMismatch);
        }
        if self.completed_at > now
            || self.completed_at >= self.deadline
            || now >= self.deadline
            || self.deadline.duration_since(self.completed_at) > MAX_REAUTH_WINDOW
        {
            return Err(ReauthenticationError::Expired);
        }
        Ok(())
    }

    fn facts_for(
        self,
        challenge_digest: [u8; 32],
        uid: u32,
        qualified_fingerprint: [u8; 32],
        now: Instant,
    ) -> Result<VerifiedPamFacts, ReauthenticationError> {
        self.validate_for(challenge_digest, uid, qualified_fingerprint, now)?;
        Ok(VerifiedPamFacts::from_consumed_token(
            self.challenge_digest,
            self.uid,
            self.qualified_fingerprint,
            self.authenticated_at_unix_ms,
        ))
    }

    /// Creates a mock-only PAM token for non-production test-support builds.
    /// This does not perform PAM or qualify the host policy.
    #[cfg(any(test, feature = "test-support"))]
    pub const fn test_fixture(
        challenge_digest: [u8; 32],
        uid: u32,
        qualified_fingerprint: [u8; 32],
        authenticated_at_unix_ms: u64,
        deadline: Instant,
        completed_at: Instant,
    ) -> Self {
        Self::verified(
            challenge_digest,
            uid,
            qualified_fingerprint,
            authenticated_at_unix_ms,
            deadline,
            completed_at,
        )
    }
}

/// Cancellation shared with a native prompt bridge and the PAM worker.
#[derive(Clone, Default)]
pub struct PamCancellation(Arc<AtomicBool>);

impl PamCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Non-secret failure category for the native reauthentication path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReauthenticationError {
    Busy,
    Cancelled,
    ClockUnavailable,
    Expired,
    IdentityUnavailable,
    InteractionRejected,
    PamRejected,
    TokenMismatch,
}

impl fmt::Display for ReauthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "another PAM reauthentication is active",
            Self::Cancelled => "PAM reauthentication was cancelled",
            Self::ClockUnavailable => "system clock cannot provide a trusted Unix timestamp",
            Self::Expired => "PAM reauthentication deadline expired",
            Self::IdentityUnavailable => "current OS identity is unavailable",
            Self::InteractionRejected => "native PAM interaction was rejected",
            Self::PamRejected => "PAM authentication or account validation failed",
            Self::TokenMismatch => "PAM reauthentication binding did not match",
        })
    }
}

impl std::error::Error for ReauthenticationError {}

/// Rejects expired, zero-length, or unbounded monotonic PAM deadlines.
///
/// # Errors
///
/// Returns [`ReauthenticationError::Expired`] for a deadline outside the accepted window.
pub fn validate_deadline(deadline: Instant) -> Result<(), ReauthenticationError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ReauthenticationError::Expired)?;
    if remaining.is_zero() || remaining > MAX_REAUTH_WINDOW {
        return Err(ReauthenticationError::Expired);
    }
    Ok(())
}

/// Native prompt bridge result. Prompt bytes are owned and zeroized by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PamInteractionError {
    Cancelled,
    Rejected,
}

#[cfg(test)]
impl FreshOsReauthentication {
    pub(crate) fn test_validate_for(
        self,
        challenge_digest: [u8; 32],
        uid: u32,
        qualified_fingerprint: [u8; 32],
        now: Instant,
    ) -> Result<VerifiedPamFacts, ReauthenticationError> {
        self.facts_for(challenge_digest, uid, qualified_fingerprint, now)
    }
}

#[cfg(test)]
mod test_shape {
    use super::*;

    const _: fn(FreshOsReauthentication) = consume_only;

    fn consume_only(token: FreshOsReauthentication) {
        drop(token);
    }
}
