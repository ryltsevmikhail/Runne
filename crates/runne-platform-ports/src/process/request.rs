//! Validated process requests and monotonic deadlines.

use super::{ProcessTypeValidationError, VerifiedCwdV1, VerifiedExecutableV1};

/// Opaque validated request supplied to a process platform port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessPlatformRequestV1 {
    request_digest: [u8; 32],
    executable: VerifiedExecutableV1,
    cwd: VerifiedCwdV1,
}

impl ProcessPlatformRequestV1 {
    /// Creates a request bound to exact verified file identities.
    ///
    /// # Errors
    /// Returns an error for an all-zero request digest.
    pub fn new(
        request_digest: [u8; 32],
        executable: VerifiedExecutableV1,
        cwd: VerifiedCwdV1,
    ) -> Result<Self, ProcessTypeValidationError> {
        if request_digest == [0; 32] {
            return Err(ProcessTypeValidationError::ZeroRequestDigest);
        }
        Ok(Self {
            request_digest,
            executable,
            cwd,
        })
    }

    /// Returns the replay-safe request digest.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Returns the verified executable identity for adapter revalidation.
    #[must_use]
    pub const fn executable(&self) -> &VerifiedExecutableV1 {
        &self.executable
    }

    /// Returns the verified working-directory identity for adapter revalidation.
    #[must_use]
    pub const fn cwd(&self) -> &VerifiedCwdV1 {
        &self.cwd
    }
}

/// Typed failures while constructing or evaluating a monotonic deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonotonicDeadlineErrorV1 {
    /// A zero budget cannot bound an effect.
    ZeroDeadlineBudget,
    /// The expiry tick cannot be represented without wrapping.
    MonotonicDeadlineOverflow,
    /// A later check supplied a tick before the dispatch start.
    MonotonicClockRegressed,
}

/// Monotonic deadline represented without wall-clock semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MonotonicDeadline {
    started_at: u64,
    expires_at: u64,
}

impl MonotonicDeadline {
    /// Creates a strictly future deadline from a dispatch start and budget.
    ///
    /// # Errors
    /// Returns [`MonotonicDeadlineErrorV1::ZeroDeadlineBudget`] when `budget` is
    /// zero, or [`MonotonicDeadlineErrorV1::MonotonicDeadlineOverflow`] when the
    /// expiry tick cannot be represented.
    pub const fn checked_after(
        started_at: u64,
        budget: u64,
    ) -> Result<Self, MonotonicDeadlineErrorV1> {
        if budget == 0 {
            return Err(MonotonicDeadlineErrorV1::ZeroDeadlineBudget);
        }
        match started_at.checked_add(budget) {
            Some(expires_at) => Ok(Self {
                started_at,
                expires_at,
            }),
            None => Err(MonotonicDeadlineErrorV1::MonotonicDeadlineOverflow),
        }
    }

    /// Creates an immediate deadline for a forced grace-overflow fallback.
    #[must_use]
    pub const fn current(now: u64) -> Self {
        Self {
            started_at: now,
            expires_at: now,
        }
    }

    /// Returns the exact tick at which this deadline was established.
    #[must_use]
    pub const fn started_at(self) -> u64 {
        self.started_at
    }

    /// Returns the exact expiry tick.
    #[must_use]
    pub const fn expires_at(self) -> u64 {
        self.expires_at
    }

    /// Returns whether the deadline is reached, rejecting a regressed clock.
    ///
    /// # Errors
    /// Returns [`MonotonicDeadlineErrorV1::MonotonicClockRegressed`] when `now`
    /// precedes this deadline's dispatch start.
    pub const fn is_reached(self, now: u64) -> Result<bool, MonotonicDeadlineErrorV1> {
        if now < self.started_at {
            return Err(MonotonicDeadlineErrorV1::MonotonicClockRegressed);
        }
        Ok(now >= self.expires_at)
    }
}
