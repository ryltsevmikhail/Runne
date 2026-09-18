//! Subscription quota evidence and admission contract.

use thiserror::Error;

/// Source of a subscription quota observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaSourceV1 {
    /// Provider usage API.
    ProviderApi,
    /// Explicit owner supplied local snapshot.
    LocalConfig,
    /// No trusted observation is available.
    Unknown,
}

/// Unit used by a provider subscription window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaUnitV1 {
    /// Input/output tokens.
    Tokens,
    /// Provider-owned credits.
    Credits,
}

/// Closed quota admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum QuotaAdmissionError {
    /// Snapshot is absent or schema was not recognized.
    #[error("subscription quota is unknown")]
    Unknown,
    /// Trusted snapshot says the window is exhausted.
    #[error("subscription quota exhausted")]
    Exhausted,
    /// Snapshot contains contradictory counters.
    #[error("subscription quota snapshot invalid")]
    Invalid,
}

/// Bounded provider subscription-window snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionQuotaSnapshotV1 {
    source: QuotaSourceV1,
    unit: QuotaUnitV1,
    used: u64,
    limit: u64,
    remaining: u64,
    reset_at_unix_seconds: u64,
    observed_at_unix_seconds: u64,
}

impl SubscriptionQuotaSnapshotV1 {
    /// Constructs and validates one trusted snapshot.
    ///
    /// # Errors
    /// Returns `Invalid` when counters or timestamps are contradictory or absent.
    pub fn new(
        source: QuotaSourceV1,
        unit: QuotaUnitV1,
        used: u64,
        limit: u64,
        remaining: u64,
        reset_at_unix_seconds: u64,
        observed_at_unix_seconds: u64,
    ) -> Result<Self, QuotaAdmissionError> {
        if source == QuotaSourceV1::Unknown
            || limit == 0
            || used > limit
            || remaining > limit
            || used.checked_add(remaining) != Some(limit)
            || reset_at_unix_seconds == 0
            || observed_at_unix_seconds == 0
        {
            return Err(QuotaAdmissionError::Invalid);
        }
        Ok(Self {
            source,
            unit,
            used,
            limit,
            remaining,
            reset_at_unix_seconds,
            observed_at_unix_seconds,
        })
    }
    /// Returns the observation source.
    #[must_use]
    pub const fn source(self) -> QuotaSourceV1 {
        self.source
    }
    /// Returns the accounting unit.
    #[must_use]
    pub const fn unit(self) -> QuotaUnitV1 {
        self.unit
    }
    /// Returns consumed amount.
    #[must_use]
    pub const fn used(self) -> u64 {
        self.used
    }
    /// Returns window limit.
    #[must_use]
    pub const fn limit(self) -> u64 {
        self.limit
    }
    /// Returns trusted remaining amount.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.remaining
    }
    /// Returns window reset timestamp.
    #[must_use]
    pub const fn reset_at_unix_seconds(self) -> u64 {
        self.reset_at_unix_seconds
    }
    /// Returns observation timestamp.
    #[must_use]
    pub const fn observed_at_unix_seconds(self) -> u64 {
        self.observed_at_unix_seconds
    }
    /// Admits a bounded reservation and denies unknown/exhausted windows.
    ///
    /// # Errors
    /// Returns `Exhausted` when the reservation is zero or exceeds remaining quota.
    pub const fn admit(self, reservation: u64) -> Result<(), QuotaAdmissionError> {
        if reservation == 0 || reservation > self.remaining {
            Err(QuotaAdmissionError::Exhausted)
        } else {
            Ok(())
        }
    }
}

/// A source that can refresh provider-owned quota without exposing credentials.
pub trait SubscriptionQuotaReader: Send + Sync {
    /// Returns a validated snapshot or a closed error.
    ///
    /// # Errors
    /// Returns the closed admission error when no valid snapshot is available.
    fn read(&self) -> Result<SubscriptionQuotaSnapshotV1, QuotaAdmissionError>;
}
